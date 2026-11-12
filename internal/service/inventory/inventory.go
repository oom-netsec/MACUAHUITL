// Package inventory es el servicio gRPC de inventario: los equipos que la app ya conoce (fase 19, solo lee
// outputs/ y los output_dir de los trabajos) más la libreta de hosts (fase 29b), su fuente «manual», con su
// export/import. Nunca habla con los equipos y nunca guarda un secreto: la credencial es una referencia a la bóveda.
package inventory

import (
	"context"
	"slices"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/devices"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
	"github.com/oom-netsec/MACUAHUITL/internal/service"
	"github.com/oom-netsec/MACUAHUITL/internal/vault"
)

type svc struct {
	v1.UnimplementedInventoryServiceServer
	d    service.Deps
	now  func() time.Time // nil = d.Now; las pruebas lo fijan para vencer tokens
	pend service.Pending[previa]
}

// Module registra el servicio de inventario.
type Module struct{}

func (Module) Register(s ipc.Registrar, d service.Deps) {
	v1.RegisterInventoryServiceServer(s, &svc{d: d})
}

// ListDevices: Device.Id es la dirección, o «nombre:<host>» si solo se conoce por respaldos sin IPv4 en la carpeta;
// en un equipo con host de la libreta es el id de ese host (con el que se edita o se borra). Los hosts de la
// libreta se fusionan por dirección con lo descubierto y suman la fuente «manual».
func (s *svc) ListDevices(_ context.Context, r *v1.ListDevicesRequest) (*v1.ListDevicesResponse, error) {
	s.d.MarkActive()
	hosts, err := loadHosts(s.d.DB())
	if err != nil {
		return nil, internal(err)
	}
	if r.ManualOnly {
		return s.listManual(hosts, r), nil
	}
	res, err := devices.Collect(s.d.Outputs(), service.JobOutputRoots(s.d)...)
	if err != nil {
		if len(hosts) == 0 {
			return nil, status.Error(codes.FailedPrecondition, err.Error())
		}
		res = devices.Result{Warnings: []string{err.Error()}} // la libreta se ve aunque aún no haya evidencia
	}
	infos := s.credsFor(hosts)
	out := &v1.ListDevicesResponse{Warnings: res.Warnings}
	for _, e := range devices.FilterEntries(devices.Merge(res.Devices, hosts), r.Query, r.Folder, r.Tag) {
		id := e.Address
		if id == "" {
			id = "nombre:" + e.Hostname
		}
		k := &v1.Device{Id: id, Hostname: e.Hostname, Platform: e.Platform, Sources: e.Sources, Target: &v1.Target{Address: e.Address}}
		if !e.LastSeen.IsZero() {
			k.LastSeenMs = e.LastSeen.UnixMilli()
		}
		if h := e.Host; h != nil {
			hostPB(k, *h, infos)
		}
		out.Devices = append(out.Devices, k)
	}
	return out, nil
}

// credsFor lee la bóveda solo si algún host tiene credencial.
func (s *svc) credsFor(hosts []devices.Host) []vault.Info {
	for _, h := range hosts {
		if h.CredentialID != "" {
			infos, _ := s.creds()
			return infos
		}
	}
	return nil
}

// hostPB pone en k los datos propios de un host de la libreta.
func hostPB(k *v1.Device, h devices.Host, infos []vault.Info) {
	k.Id, k.Name, k.Profile, k.Folder, k.Tags, k.Notes = h.ID, h.Name, portPB(h), h.Folder, h.Tags, h.Notes
	k.CredentialId, k.CredentialLabel = h.CredentialID, labelOf(infos, h.CredentialID)
}

// listManual devuelve solo los hosts de la libreta con sus propios valores (sin fusionar con lo descubierto),
// por nombre sin importar mayúsculas. query busca solo en esos valores. No lee outputs/.
func (s *svc) listManual(hosts []devices.Host, r *v1.ListDevicesRequest) *v1.ListDevicesResponse {
	es := make([]devices.Entry, len(hosts))
	for i := range hosts {
		h := hosts[i]
		es[i] = devices.Entry{Device: devices.Device{Address: h.Address, Hostname: h.Name, Platform: h.Platform}, Host: &h}
	}
	es = devices.FilterEntries(es, r.Query, r.Folder, r.Tag)
	slices.SortFunc(es, func(a, b devices.Entry) int {
		return strings.Compare(devices.NameKey(a.Host.Name)+"\x00"+a.Host.ID, devices.NameKey(b.Host.Name)+"\x00"+b.Host.ID)
	})
	infos := s.credsFor(hosts)
	out := &v1.ListDevicesResponse{}
	for _, e := range es {
		k := &v1.Device{Hostname: e.Host.Name, Platform: e.Host.Platform, Sources: []string{devices.SrcManual}, Target: &v1.Target{Address: e.Host.Address}}
		hostPB(k, *e.Host, infos)
		out.Devices = append(out.Devices, k)
	}
	return out
}
