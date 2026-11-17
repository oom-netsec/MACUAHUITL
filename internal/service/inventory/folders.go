package inventory

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"google.golang.org/grpc/codes"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/devices"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/service"
)

// Carpetas de hosts (fase 44d). Viven en host_folders (única sin distinguir mayúsculas); hosts.folder es el
// nombre. Invariante, mantenido en cada transacción: todo hosts.folder no vacío existe en host_folders con el
// mismo texto. Aquí todo va con tx (el núcleo tiene una sola conexión) y se audita después del Commit.
const (
	maxFolders   = 1000
	maxMoveIDs   = 5000
	moveAuditIDs = 50
)

// storedFolder da el nombre guardado de una carpeta (sin distinguir mayúsculas); ok es false si no existe.
func storedFolder(q querier, name string) (stored string, ok bool, err error) {
	err = q.QueryRow(`SELECT name FROM host_folders WHERE name = ?`, name).Scan(&stored)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	return stored, err == nil, err
}

// ensureFolder devuelve el nombre guardado de name y lo crea si falta (created es entonces el nombre; si no, "").
// Vacío es «sin carpeta». name ya viene validado.
func ensureFolder(ctx context.Context, q querier, name string, now time.Time) (stored, created string, err error) {
	if name == "" {
		return "", "", nil
	}
	stored, ok, err := storedFolder(q, name)
	if err != nil {
		return "", "", internal(err)
	}
	if ok {
		return stored, "", nil
	}
	var n int
	if err := q.QueryRow(`SELECT count(*) FROM host_folders`).Scan(&n); err != nil {
		return "", "", internal(err)
	}
	if n >= maxFolders {
		return "", "", service.Err(ctx, codes.ResourceExhausted, "hosts.err.folders_full", i18n.A("max", maxFolders))
	}
	if _, err := q.Exec(`INSERT INTO host_folders(name, created_at) VALUES(?, ?)`, name, now.UTC().Format(fechaFmt)); err != nil {
		return "", "", internal(err)
	}
	return name, name, nil
}

// ensureHostFolders deja cada host con el nombre guardado de su carpeta, creando las que falten; da las creadas.
func ensureHostFolders(ctx context.Context, q querier, hs []devices.Host, now time.Time) (created []string, err error) {
	for i := range hs {
		var c string
		if hs[i].Folder, c, err = ensureFolder(ctx, q, hs[i].Folder, now); err != nil {
			return nil, err
		}
		if c != "" {
			created = append(created, c)
		}
	}
	return created, nil
}

func (s *svc) auditNewFolders(origin string, names ...string) {
	for _, n := range names {
		if n != "" {
			s.d.Audit("hostfolder.create", n, "origin="+origin)
		}
	}
}

func folderPB(q querier, name string) (*v1.HostFolder, error) {
	f := &v1.HostFolder{Name: name}
	err := q.QueryRow(`SELECT count(*) FROM hosts WHERE folder = ? COLLATE NOCASE`, name).Scan(&f.HostCount)
	return f, err
}

func (s *svc) ListHostFolders(ctx context.Context, _ *v1.ListHostFoldersRequest) (*v1.ListHostFoldersResponse, error) {
	s.d.MarkActive()
	rows, err := s.d.DB().Query(`SELECT f.name, count(h.id) FROM host_folders f LEFT JOIN hosts h ON f.name = h.folder
		GROUP BY f.name ORDER BY f.name COLLATE NOCASE`)
	if err != nil {
		return nil, internal(err)
	}
	defer rows.Close()
	out := &v1.ListHostFoldersResponse{}
	for rows.Next() {
		f := &v1.HostFolder{}
		if err := rows.Scan(&f.Name, &f.HostCount); err != nil {
			return nil, internal(err)
		}
		out.Folders = append(out.Folders, f)
	}
	if err := rows.Err(); err != nil {
		return nil, internal(err)
	}
	return out, nil
}

func (s *svc) CreateHostFolder(ctx context.Context, r *v1.CreateHostFolderRequest) (*v1.CreateHostFolderResponse, error) {
	s.d.MarkActive()
	name, err := devices.CleanFolder(r.Name)
	if err != nil {
		return nil, service.ErrFrom(ctx, codes.InvalidArgument, err)
	}
	var created string
	err = s.tx(func(tx *sql.Tx) error {
		if _, ok, err := storedFolder(tx, name); err != nil {
			return internal(err)
		} else if ok {
			return service.Err(ctx, codes.AlreadyExists, "hosts.err.folder_exists", i18n.A("name", name))
		}
		var err error
		_, created, err = ensureFolder(ctx, tx, name, s.clock())
		return err
	})
	if err != nil {
		return nil, err
	}
	s.auditNewFolders("user", created)
	return &v1.CreateHostFolderResponse{Folder: &v1.HostFolder{Name: name}}, nil
}

func (s *svc) RenameHostFolder(ctx context.Context, r *v1.RenameHostFolderRequest) (*v1.RenameHostFolderResponse, error) {
	s.d.MarkActive()
	to, err := devices.CleanFolder(r.NewName)
	if err != nil {
		return nil, service.ErrFrom(ctx, codes.InvalidArgument, err)
	}
	var old string
	var out *v1.HostFolder
	err = s.tx(func(tx *sql.Tx) error {
		var ok bool
		var err error
		if old, ok, err = storedFolder(tx, r.Name); err != nil {
			return internal(err)
		} else if !ok {
			return service.Err(ctx, codes.NotFound, "hosts.err.folder_no", i18n.A("name", r.Name))
		}
		if !strings.EqualFold(old, to) { // solo cambiar mayúsculas no choca con nadie
			if _, ok, err := storedFolder(tx, to); err != nil {
				return internal(err)
			} else if ok {
				return service.Err(ctx, codes.AlreadyExists, "hosts.err.folder_exists", i18n.A("name", to))
			}
		}
		if _, err := tx.Exec(`UPDATE host_folders SET name = ? WHERE name = ?`, to, old); err != nil {
			return internal(err)
		}
		if _, err := tx.Exec(`UPDATE hosts SET folder = ? WHERE folder = ? COLLATE NOCASE`, to, old); err != nil {
			return internal(err)
		}
		if out, err = folderPB(tx, to); err != nil {
			return internal(err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	s.d.Audit("hostfolder.rename", old, fmt.Sprintf("to=%q hosts=%d", to, out.HostCount))
	return &v1.RenameHostFolderResponse{Folder: out}, nil
}

func (s *svc) DeleteHostFolder(ctx context.Context, r *v1.DeleteHostFolderRequest) (*v1.DeleteHostFolderResponse, error) {
	s.d.MarkActive()
	var name string
	var n int32
	err := s.tx(func(tx *sql.Tx) error {
		var ok bool
		var err error
		if name, ok, err = storedFolder(tx, r.Name); err != nil {
			return internal(err)
		} else if !ok {
			return service.Err(ctx, codes.NotFound, "hosts.err.folder_no", i18n.A("name", r.Name))
		}
		f, err := folderPB(tx, name)
		if err != nil {
			return internal(err)
		}
		if n = f.HostCount; n > 0 && !r.Confirm {
			return service.Err(ctx, codes.FailedPrecondition, "hosts.err.folder_not_empty", i18n.A("name", name, "host_count", n))
		}
		if _, err := tx.Exec(`UPDATE hosts SET folder = '' WHERE folder = ? COLLATE NOCASE`, name); err != nil {
			return internal(err)
		}
		if _, err := tx.Exec(`DELETE FROM host_folders WHERE name = ?`, name); err != nil {
			return internal(err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	s.d.Audit("hostfolder.delete", name, fmt.Sprintf("unfiled=%d", n))
	return &v1.DeleteHostFolderResponse{HostsUnfiled: n}, nil
}

func (s *svc) MoveHosts(ctx context.Context, r *v1.MoveHostsRequest) (*v1.MoveHostsResponse, error) {
	s.d.MarkActive()
	if len(r.Ids) < 1 || len(r.Ids) > maxMoveIDs {
		return nil, service.Err(ctx, codes.InvalidArgument, "hosts.err.move_ids", i18n.A("max", maxMoveIDs))
	}
	to := r.Folder
	if to != "" {
		var err error
		if to, err = devices.CleanFolder(to); err != nil {
			return nil, service.ErrFrom(ctx, codes.InvalidArgument, err)
		}
	}
	seen := map[string]bool{}
	var ids []string
	for _, id := range r.Ids {
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	var created string
	var moved int32
	var movedIDs []string
	err := s.tx(func(tx *sql.Tx) error {
		for _, id := range ids {
			var f string
			if err := tx.QueryRow(`SELECT folder FROM hosts WHERE id = ?`, id).Scan(&f); errors.Is(err, sql.ErrNoRows) {
				return service.Err(ctx, codes.NotFound, "hosts.err.no_id", i18n.A("id", id))
			} else if err != nil {
				return internal(err)
			}
		}
		var err error
		if to, created, err = ensureFolder(ctx, tx, to, s.clock()); err != nil {
			return err
		}
		for _, id := range ids {
			res, err := tx.Exec(`UPDATE hosts SET folder = ? WHERE id = ? AND folder <> ?`, to, id, to)
			if err != nil {
				return internal(err)
			}
			if n, _ := res.RowsAffected(); n > 0 {
				moved++
				movedIDs = append(movedIDs, id)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	s.auditNewFolders("move", created)
	target, detail := to, fmt.Sprintf("n=%d", moved)
	if target == "" {
		target = "-"
	}
	if moved > 0 {
		shown := movedIDs
		if len(shown) > moveAuditIDs {
			shown = shown[:moveAuditIDs]
		}
		detail += " ids=" + strings.Join(shown, ",")
		if len(shown) < len(movedIDs) {
			detail += "..."
		}
	}
	s.d.Audit("hosts.move", target, detail)
	return &v1.MoveHostsResponse{Moved: moved, FolderCreated: created != ""}, nil
}
