package service

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"

	"google.golang.org/grpc/codes"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/sys"
)

// CheckRunDir valida la carpeta de una corrida que el cliente nombra en vez de un id de trabajo (el trabajo ya se quitó del
// historial). Acepta una ruta arbitraria, así que es estricta: absoluta y sin «..», con los enlaces resueltos, fuera de las
// carpetas reservadas (la misma regla que CheckOutputs), dentro de Outputs() o de las raíces de los trabajos (JobOutputRoots)
// y con el manifest.json de la corrida, que prueba que terminó. Devuelve la ruta real y el id del trabajo que dice el manifest
// (vacío en una corrida vieja que no lo trae).
func CheckRunDir(ctx context.Context, d Deps, dir string) (real, jobID string, err error) {
	if real, err = resolveDir(dir, d.Settings()); err != nil {
		return "", "", ErrFrom(ctx, codes.InvalidArgument, err)
	}
	ok := false
	for _, r := range append([]string{d.Outputs()}, JobOutputRoots(d)...) {
		if inside(real, resolve(r)) {
			ok = true
			break
		}
	}
	if !ok {
		return "", "", Err(ctx, codes.InvalidArgument, "backup.err.dir_fuera", i18n.A("dir", real))
	}
	mp := filepath.Join(real, "manifest.json")
	if fi, e := os.Lstat(mp); e != nil || !fi.Mode().IsRegular() {
		return "", "", Err(ctx, codes.InvalidArgument, "backup.err.dir_sin_manifest", i18n.A("dir", real))
	}
	f, e := sys.OpenRegular(mp)
	if e != nil {
		return "", "", Err(ctx, codes.InvalidArgument, "backup.err.dir_sin_manifest", i18n.A("dir", real))
	}
	defer f.Close()
	var m struct {
		JobID string `json:"job_id"`
	}
	if json.NewDecoder(io.LimitReader(f, 8<<20)).Decode(&m) != nil {
		return "", "", Err(ctx, codes.InvalidArgument, "backup.err.dir_sin_manifest", i18n.A("dir", real))
	}
	return real, m.JobID, nil
}
