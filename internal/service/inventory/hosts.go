package inventory

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/devices"
	"github.com/oom-netsec/MACUAHUITL/internal/vault"
)

func internal(err error) error { return status.Error(codes.Internal, err.Error()) }

func (s *svc) clock() time.Time {
	if s.now != nil {
		return s.now()
	}
	return s.d.Now()
}

func (s *svc) tx(f func(tx *sql.Tx) error) error {
	tx, err := s.d.DB().Begin()
	if err != nil {
		return internal(err)
	}
	defer tx.Rollback()
	if err := f(tx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return internal(err)
	}
	return nil
}

// creds son las credenciales de la bóveda sin secretos (las reservadas del sistema no salen en List). ok es
// false si no hay bóveda o está cerrada.
func (s *svc) creds() (infos []vault.Info, ok bool) {
	v := s.d.Vault()
	if v == nil {
		return nil, false
	}
	l, err := v.List()
	return l, err == nil
}

func labelOf(infos []vault.Info, id string) string {
	for _, i := range infos {
		if i.ID == id {
			return i.Label
		}
	}
	return ""
}

func hostFromPB(p *v1.Device) devices.Host {
	h := devices.Host{Name: p.Name, Address: p.GetTarget().GetAddress(), Port: int(p.GetProfile().GetPort()), Platform: p.Platform, Folder: p.Folder,
		Tags: append([]string{}, p.Tags...), CredentialID: p.CredentialId, Notes: p.Notes}
	return h
}

func portPB(h devices.Host) *v1.DeviceProfile { return &v1.DeviceProfile{Port: uint32(h.Port)} }

// auditHost anota sin notas ni credencial: solo quién es y adónde apunta.
func (s *svc) auditHost(action string, h devices.Host) {
	s.d.Audit(action, h.ID, fmt.Sprintf("%s %s:%s", h.Name, h.Address, strconv.Itoa(h.Port)))
}

// PutDevice crea (id vacío) o edita un host de la libreta. El nombre y el destino (dirección y puerto) no se repiten.
func (s *svc) PutDevice(_ context.Context, r *v1.PutDeviceRequest) (*v1.PutDeviceResponse, error) {
	s.d.MarkActive()
	if r.Device == nil {
		return nil, status.Error(codes.InvalidArgument, "falta el host")
	}
	h, err := devices.Clean(hostFromPB(r.Device))
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	out := &v1.PutDeviceResponse{}
	if h.CredentialID != "" {
		infos, ok := s.creds()
		switch {
		case !ok:
			out.Warnings = append(out.Warnings, "la bóveda está cerrada: la credencial se guardó sin validar")
		case labelOf(infos, h.CredentialID) == "":
			return nil, status.Error(codes.InvalidArgument, "la credencial no existe en la bóveda (o es una entrada del sistema)")
		}
	}
	now := s.clock().UTC().Truncate(time.Second)
	action := "hosts.crear"
	err = s.tx(func(tx *sql.Tx) error {
		all, err := loadHosts(tx)
		if err != nil {
			return internal(err)
		}
		h.ID, h.CreatedAt, h.UpdatedAt = r.Device.Id, now, now
		if h.ID == "" {
			if len(all) >= devices.MaxHosts {
				return status.Errorf(codes.ResourceExhausted, "la libreta llegó a %d hosts", devices.MaxHosts)
			}
			h.ID = devices.NewID()
		} else {
			old, err := getHost(tx, h.ID)
			if errors.Is(err, sql.ErrNoRows) {
				return status.Errorf(codes.NotFound, "no hay un host de la libreta con id %q", h.ID)
			}
			if err != nil {
				return internal(err)
			}
			h.CreatedAt, action = old.CreatedAt, "hosts.editar"
		}
		for _, o := range all {
			switch {
			case o.ID == h.ID:
			case devices.NameKey(o.Name) == devices.NameKey(h.Name):
				return status.Errorf(codes.AlreadyExists, "ya hay un host llamado %q", o.Name)
			case devices.Key(o) == devices.Key(h):
				return status.Errorf(codes.AlreadyExists, "%q ya está en la libreta como %q", devices.Key(h), o.Name)
			}
		}
		if err := putHost(tx, h); err != nil {
			return internal(err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	s.auditHost(action, h)
	out.Id = h.ID
	return out, nil
}

// DeleteDevice borra un host de la libreta; la evidencia de las otras fuentes no se toca.
func (s *svc) DeleteDevice(_ context.Context, r *v1.DeleteDeviceRequest) (*v1.DeleteDeviceResponse, error) {
	s.d.MarkActive()
	var h devices.Host
	err := s.tx(func(tx *sql.Tx) error {
		var err error
		if h, err = getHost(tx, r.Id); errors.Is(err, sql.ErrNoRows) {
			return status.Errorf(codes.NotFound, "no hay un host de la libreta con id %q", r.Id)
		} else if err != nil {
			return internal(err)
		}
		if _, err := tx.Exec(`DELETE FROM hosts WHERE id = ?`, r.Id); err != nil {
			return internal(err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	s.auditHost("hosts.borrar", h)
	return &v1.DeleteDeviceResponse{}, nil
}
