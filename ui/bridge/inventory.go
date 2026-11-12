package bridge

import (
	"context"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
)

// ---- Equipos conocidos (Fase 19): para los selectores y la lista de IP permitidas ----

type KnownDeviceDTO struct {
	Address    string   `json:"address"` // vacío si solo se conoce por sus respaldos
	Hostname   string   `json:"hostname"`
	Platform   string   `json:"platform"`
	LastSeenMs int64    `json:"lastSeenMs"` // 0 = nunca se alcanzó
	Sources    []string `json:"sources"`    // patrol, flota, respaldos, manual

	// Libreta de hosts (fase 29b). Solo los equipos con host manual (sources incluye «manual») traen name, port,
	// folder, credentialId, credentialLabel y notes; ID es el del host manual (con él se edita o se borra) y, en los
	// demás, la dirección o «nombre:<host>». tags va siempre como arreglo.
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Port            int      `json:"port"`
	Folder          string   `json:"folder"`
	Tags            []string `json:"tags"`
	CredentialID    string   `json:"credentialId"`
	CredentialLabel string   `json:"credentialLabel"`
	Notes           string   `json:"notes"`
}

type KnownDevicesDTO struct {
	Devices  []KnownDeviceDTO `json:"devices"`
	Warnings []string         `json:"warnings"`
}

func inventoryClient(c *ipc.ClientConn) v1.InventoryServiceClient {
	return v1.NewInventoryServiceClient(c)
}

func knownDeviceDTO(d *v1.Device) KnownDeviceDTO {
	return KnownDeviceDTO{Address: d.GetTarget().GetAddress(), Hostname: d.Hostname, Platform: d.Platform, LastSeenMs: d.LastSeenMs, Sources: strs(d.Sources),
		ID: d.Id, Name: d.Name, Port: int(d.GetProfile().GetPort()), Folder: d.Folder, Tags: strs(d.Tags), CredentialID: d.CredentialId, CredentialLabel: d.CredentialLabel, Notes: d.Notes}
}

// ListDevices junta los equipos de los trabajos de Patrol, la flota, los respaldos y la libreta de hosts, sin duplicados.
func (b *Bridge) ListDevices(query string) (KnownDevicesDTO, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (KnownDevicesDTO, error) {
		r, err := inventoryClient(c).ListDevices(ctx, &v1.ListDevicesRequest{Query: query})
		out := KnownDevicesDTO{Devices: []KnownDeviceDTO{}, Warnings: strs(r.GetWarnings())}
		for _, d := range r.GetDevices() {
			out.Devices = append(out.Devices, knownDeviceDTO(d))
		}
		return out, err
	})
}

// ---- Libreta de hosts (fase 29b): la fuente «manual» del inventario ----
// Una credencial es solo la referencia (credentialId) a la bóveda; nunca un secreto. Las listas van como [].

// HostDTO es un host de la libreta. credentialLabel es de solo lectura: al guardar se ignora.
type HostDTO struct {
	ID              string   `json:"id"` // vacío al crear
	Name            string   `json:"name"`
	Address         string   `json:"address"`
	Port            int      `json:"port"` // 0 = 22
	Platform        string   `json:"platform"`
	Folder          string   `json:"folder"`
	Tags            []string `json:"tags"`
	CredentialID    string   `json:"credentialId"`
	CredentialLabel string   `json:"credentialLabel"`
	Notes           string   `json:"notes"`
}

type SaveHostResultDTO struct {
	ID       string   `json:"id"`
	Warnings []string `json:"warnings"` // p. ej. bóveda cerrada: la credencial no se validó
}

type ExportHostsResultDTO struct {
	Count    int      `json:"count"`
	Warnings []string `json:"warnings"`
}

type HostImportItemDTO struct {
	Host              HostDTO `json:"host"`
	Key               string  `json:"key"`    // «dirección:puerto»: identifica al host en las decisiones
	State             string  `json:"state"`  // nuevo | igual | conflicto
	Reason            string  `json:"reason"` // solo en conflicto: direccion (reemplazar u omitir) | nombre (también renombrar)
	ConflictsWith     string  `json:"conflictsWith"`
	CredentialMissing bool    `json:"credentialMissing"` // trae etiqueta pero no hay credencial con ella: quedaría sin credencial
}

// HostImportErrorDTO es una fila (CSV) o entrada (JSON) inválida; no bloquea las demás.
type HostImportErrorDTO struct {
	Line   int    `json:"line"`  // CSV: línea del archivo (el encabezado es la 1); JSON: posición, desde 1, dentro de «hosts»
	Field  string `json:"field"` // name, address, port… ; vacío = la fila entera
	Reason string `json:"reason"`
}

type HostsImportPreviewDTO struct {
	Token     string               `json:"token"` // 10 minutos, un solo uso
	ExpiresMs int64                `json:"expiresMs"`
	Format    string               `json:"format"` // csv | json, el detectado
	Items     []HostImportItemDTO  `json:"items"`  // solo las filas válidas
	Errors    []HostImportErrorDTO `json:"errors"` // las inválidas; al aplicar cuentan como omitidas
	Warnings  []string             `json:"warnings"`
}

type HostsImportResultDTO struct {
	Created  int `json:"created"`
	Replaced int `json:"replaced"`
	Renamed  int `json:"renamed"`
	Skipped  int `json:"skipped"` // incluye los igual y las filas inválidas
	Invalid  int `json:"invalid"` // de skipped, las filas inválidas de la vista previa
}

type HostsTemplateDTO struct {
	Format   string `json:"format"`
	Filename string `json:"filename"` // sugerido, p. ej. hosts-plantilla.csv
	Content  string `json:"content"`  // UTF-8; el JSON va sin sha256
}

type HostFieldDTO struct {
	Name        string `json:"name"` // columna del CSV y clave del JSON
	Type        string `json:"type"` // texto | entero | lista
	Required    bool   `json:"required"`
	Example     string `json:"example"`
	Description string `json:"description"`
}

type HostsFormatDTO struct {
	Fields   []HostFieldDTO `json:"fields"` // en el orden del encabezado del CSV
	MaxRows  int            `json:"maxRows"`
	MaxBytes int64          `json:"maxBytes"`
}

type HostDecisionDTO struct {
	Key    string `json:"key"`
	Action string `json:"action"` // renombrar | reemplazar | omitir
}

func hostDTO(d *v1.Device) HostDTO {
	return HostDTO{ID: d.GetId(), Name: d.GetName(), Address: d.GetTarget().GetAddress(), Port: int(d.GetProfile().GetPort()), Platform: d.GetPlatform(), Folder: d.GetFolder(),
		Tags: strs(d.GetTags()), CredentialID: d.GetCredentialId(), CredentialLabel: d.GetCredentialLabel(), Notes: d.GetNotes()}
}

// ListHosts devuelve solo los hosts de la libreta con SUS valores (sin fusionar con lo descubierto: es lo que se edita),
// por nombre sin importar mayúsculas; query, folder y tag filtran (vacío = sin filtro) y query busca solo en los valores del host.
func (b *Bridge) ListHosts(query, folder, tag string) ([]HostDTO, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) ([]HostDTO, error) {
		r, err := inventoryClient(c).ListDevices(ctx, &v1.ListDevicesRequest{Query: query, Folder: folder, Tag: tag, ManualOnly: true})
		out := []HostDTO{}
		for _, d := range r.GetDevices() {
			out = append(out, hostDTO(d))
		}
		return out, err
	})
}

// SaveHost crea (id vacío) o edita un host de la libreta.
func (b *Bridge) SaveHost(h HostDTO) (SaveHostResultDTO, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (SaveHostResultDTO, error) {
		r, err := inventoryClient(c).PutDevice(ctx, &v1.PutDeviceRequest{Device: &v1.Device{Id: h.ID, Name: h.Name, Target: &v1.Target{Address: h.Address},
			Profile: &v1.DeviceProfile{Port: uint32(h.Port)}, Platform: h.Platform, Folder: h.Folder, Tags: h.Tags, CredentialId: h.CredentialID, Notes: h.Notes}})
		return SaveHostResultDTO{ID: r.GetId(), Warnings: strs(r.GetWarnings())}, err
	})
}

// DeleteHost borra un host de la libreta; la evidencia de las otras fuentes no se toca.
func (b *Bridge) DeleteHost(id string) error {
	_, err := call(b, func(ctx context.Context, c *ipc.ClientConn) (struct{}, error) {
		_, err := inventoryClient(c).DeleteDevice(ctx, &v1.DeleteDeviceRequest{Id: id})
		return struct{}{}, err
	})
	return err
}

// ExportHosts escribe los hosts elegidos (ninguno = todos) en path (absoluta; el núcleo la crea 0600 y no sobrescribe sin overwrite).
// format es csv o json; vacío = por la extensión de path.
func (b *Bridge) ExportHosts(ids []string, path string, overwrite bool, format string) (ExportHostsResultDTO, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (ExportHostsResultDTO, error) {
		r, err := inventoryClient(c).ExportHosts(ctx, &v1.ExportHostsRequest{Ids: ids, Path: path, Overwrite: overwrite, Format: format})
		return ExportHostsResultDTO{Count: int(r.GetCount()), Warnings: strs(r.GetWarnings())}, err
	})
}

// PreviewHostsImport valida el archivo y da el estado de cada host válido y el error de cada fila inválida; no escribe nada.
// format es csv o json; vacío = por la extensión de path.
func (b *Bridge) PreviewHostsImport(path, format string) (HostsImportPreviewDTO, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (HostsImportPreviewDTO, error) {
		r, err := inventoryClient(c).PreviewImportHosts(ctx, &v1.PreviewImportHostsRequest{Path: path, Format: format})
		out := HostsImportPreviewDTO{Token: r.GetToken(), ExpiresMs: r.GetExpiresMs(), Format: r.GetFormat(), Items: []HostImportItemDTO{}, Errors: []HostImportErrorDTO{}, Warnings: strs(r.GetWarnings())}
		for _, e := range r.GetErrors() {
			out.Errors = append(out.Errors, HostImportErrorDTO{Line: int(e.GetLine()), Field: e.GetField(), Reason: e.GetReason()})
		}
		for _, it := range r.GetItems() {
			out.Items = append(out.Items, HostImportItemDTO{Host: hostDTO(it.GetHost()), Key: it.GetKey(), State: it.GetState(), Reason: it.GetReason(),
				ConflictsWith: it.GetConflictsWith(), CredentialMissing: it.GetCredentialMissing()})
		}
		return out, err
	})
}

// ApplyHostsImport aplica la vista previa con la decisión de cada conflicto.
func (b *Bridge) ApplyHostsImport(token string, decisions []HostDecisionDTO) (HostsImportResultDTO, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (HostsImportResultDTO, error) {
		ds := []*v1.ImportHostDecision{}
		for _, d := range decisions {
			ds = append(ds, &v1.ImportHostDecision{Key: d.Key, Action: d.Action})
		}
		r, err := inventoryClient(c).ApplyImportHosts(ctx, &v1.ApplyImportHostsRequest{Token: token, Decisions: ds})
		return HostsImportResultDTO{Created: int(r.GetCreated()), Replaced: int(r.GetReplaced()), Renamed: int(r.GetRenamed()), Skipped: int(r.GetSkipped()), Invalid: int(r.GetInvalid())}, err
	})
}

// HostsImportTemplate da el archivo de ejemplo (encabezado y 3 filas válidas) en csv o json.
func (b *Bridge) HostsImportTemplate(format string) (HostsTemplateDTO, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (HostsTemplateDTO, error) {
		r, err := inventoryClient(c).HostsImportTemplate(ctx, &v1.HostsImportTemplateRequest{Format: format})
		return HostsTemplateDTO{Format: r.GetFormat(), Filename: r.GetFilename(), Content: r.GetContent()}, err
	})
}

// HostsImportFormat describe los campos del archivo de import, de la misma tabla que lo valida.
func (b *Bridge) HostsImportFormat() (HostsFormatDTO, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (HostsFormatDTO, error) {
		r, err := inventoryClient(c).HostsImportFormat(ctx, &v1.HostsImportFormatRequest{})
		out := HostsFormatDTO{Fields: []HostFieldDTO{}, MaxRows: int(r.GetMaxRows()), MaxBytes: r.GetMaxBytes()}
		for _, f := range r.GetFields() {
			out.Fields = append(out.Fields, HostFieldDTO{Name: f.GetName(), Type: f.GetType(), Required: f.GetRequired(), Example: f.GetExample(), Description: f.GetDescription()})
		}
		return out, err
	})
}
