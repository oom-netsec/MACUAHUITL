package service

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"google.golang.org/grpc/codes"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/sys"
)

// AbsPath exige una ruta absoluta (la de un archivo de export/import) y la limpia.
func AbsPath(ctx context.Context, p string) (string, error) {
	if !filepath.IsAbs(p) {
		return "", Err(ctx, codes.InvalidArgument, "respaldo.err.path_abs", nil)
	}
	return filepath.Clean(p), nil
}

// WriteExport escribe el archivo de export con 0600. Sin overwrite la ruta debe ser nueva (O_EXCL no sigue
// enlaces ni pisa nada). Con overwrite solo reemplaza un archivo regular: se escribe a un temporal en la misma
// carpeta y se renombra, así un enlace simbólico en la ruta no desvía la escritura y un fallo no destruye el anterior.
func WriteExport(ctx context.Context, path string, data []byte, overwrite bool) error {
	if !overwrite {
		f, err := sys.OpenNew(path)
		if errors.Is(err, fs.ErrExist) {
			return Err(ctx, codes.AlreadyExists, "file.exists", i18n.A("path", path))
		}
		if err != nil {
			return ErrFrom(ctx, codes.FailedPrecondition, err)
		}
		_, err = f.Write(data)
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			os.Remove(path)
			return ErrFrom(ctx, codes.Internal, err)
		}
		return nil
	}
	if fi, err := os.Lstat(path); err == nil && !fi.Mode().IsRegular() {
		return Err(ctx, codes.FailedPrecondition, "file.err.export_not_regular", nil)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".export-*") // 0600
	if err != nil {
		return ErrFrom(ctx, codes.FailedPrecondition, err)
	}
	defer os.Remove(tmp.Name()) // tras el rename ya no existe
	_, err = tmp.Write(data)
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp.Name(), path)
	}
	if err != nil {
		return ErrFrom(ctx, codes.Internal, err)
	}
	return nil
}

// ReadImport lee el archivo de import: regular, sin quedarse en una FIFO, y de a lo más max bytes (más uno, para que quien llama detecte el exceso).
func ReadImport(ctx context.Context, path string, max int64) ([]byte, error) {
	f, err := sys.OpenRegular(path)
	if err != nil {
		return nil, ErrFrom(ctx, codes.FailedPrecondition, err)
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, ErrFrom(ctx, codes.Internal, err)
	}
	return b, nil
}
