// Package service define el molde de los servicios gRPC por área: la interfaz
// Deps (lo único del núcleo que ven) y Module (cómo se registran).
//
// No hace: lógica de herramientas ni importar core; el núcleo arma la lista de módulos.
package service

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"io"
	"time"

	"google.golang.org/grpc/codes"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
	"github.com/oom-netsec/MACUAHUITL/internal/transport"
	"github.com/oom-netsec/MACUAHUITL/internal/vault"
)

// JobInfo es la foto de un trabajo de Patrol: su estado y su carpeta de salida
// (vacía mientras no haya escritor, es decir, antes de armar).
type JobInfo struct {
	State string
	Dir   string
	// Until: fin de la ventana real del trabajo armado; cero antes de armar.
	Until time.Time
	// FinishErr: por qué no se pudo cerrar el trabajo (manifest, zip); vacío si cerró bien o sigue abierto.
	FinishErr string
}

// Deps es lo que el núcleo presta a los servicios. Nada más: ni jobs, ni bus, ni mutex.
type Deps interface {
	// Audit anota en la bitácora con el actor del núcleo.
	Audit(action, target, detail string)
	// ExportAudit vuelca la bitácora entre from y to como JSON por línea.
	ExportAudit(ctx context.Context, w io.Writer, from, to time.Time) error
	// MarkActive registra uso del ingeniero (reinicia el reloj de inactividad).
	MarkActive()
	Now() time.Time
	Guard() *transport.Guard
	// Vault devuelve la bóveda, o nil si aún no existe.
	Vault() *vault.Vault
	// SealParams son los parámetros KDF para sellar llaves nuevas.
	SealParams() vault.Params
	DB() *sql.DB
	// Outputs es la carpeta raíz de salidas del ingeniero; es la vigente, así que se lee en cada operación.
	Outputs() string
	// Settings son las preferencias del núcleo (carpeta de salidas y defaults de archivo de los receptores).
	Settings() *CoreSettings
	// DiagLookPath resuelve binarios de diag; nil = exec.LookPath.
	DiagLookPath() func(string) (string, error)
	// Job devuelve la foto de un trabajo de Patrol, o NotFound.
	Job(ctx context.Context, id string) (JobInfo, error) // ctx da el idioma del «trabajo no existe»
	// Patrol y ValidateJob dejan a la ventana de cambio crear y armar trabajos como cualquier cliente.
	Patrol() v1.PatrolServiceServer
	ValidateJob(context.Context, *v1.JobSpec) error
	// Hosts son las llaves de host conocidas (para los servicios que abren SSH por su cuenta).
	Hosts() *transport.KnownHosts
	// OnClose registra f para que el núcleo la corra al cerrarse, antes de cerrar la base de datos
	// (los servicios con trabajo en vuelo lo cancelan y lo esperan ahí).
	OnClose(f func())
}

// Module es un servicio de área: se registra en el servidor con las dependencias del núcleo.
type Module interface {
	Register(ipc.Registrar, Deps)
}

// NewID da un identificador corto aleatorio (trabajos, cambios).
func NewID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// VaultErr traduce los errores de la bóveda a códigos gRPC; el texto sale en el idioma del contexto.
func VaultErr(ctx context.Context, err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, vault.ErrWrongPassword):
		return ErrFrom(ctx, codes.PermissionDenied, err)
	case errors.Is(err, vault.ErrLocked):
		return ErrFrom(ctx, codes.FailedPrecondition, err)
	case errors.Is(err, vault.ErrNotFound):
		return ErrFrom(ctx, codes.NotFound, err)
	case errors.Is(err, vault.ErrEmptyPassword), errors.Is(err, vault.ErrWindowTooLong), errors.Is(err, vault.ErrReserved),
		errors.Is(err, vault.ErrNotBackup), errors.Is(err, vault.ErrShortPhrase), errors.Is(err, vault.ErrSamePhrase), errors.Is(err, vault.ErrTooManyEntries):
		return ErrFrom(ctx, codes.InvalidArgument, err)
	case errors.Is(err, vault.ErrNotRegular), errors.Is(err, vault.ErrBackupParams):
		return ErrFrom(ctx, codes.FailedPrecondition, err)
	case errors.Is(err, vault.ErrExists), errors.Is(err, vault.ErrBackupExists):
		return ErrFrom(ctx, codes.AlreadyExists, err)
	}
	return ErrFrom(ctx, codes.Internal, err)
}
