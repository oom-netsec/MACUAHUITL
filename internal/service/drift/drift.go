package drift

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/analyze"
	"github.com/oom-netsec/MACUAHUITL/internal/drift"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
	"github.com/oom-netsec/MACUAHUITL/internal/service"
	"github.com/oom-netsec/MACUAHUITL/internal/sys"
)

// driftSvc solo lee la carpeta de un trabajo de Patrol: nunca habla con los equipos.
type driftSvc struct {
	v1.UnimplementedDriftServiceServer
	d service.Deps
}

// bundle acepta el ID de un trabajo de esta sesión o la ruta absoluta de su carpeta.
func (s *driftSvc) bundle(job string) (*analyze.Bundle, error) {
	dir := filepath.Clean(job)
	if !filepath.IsAbs(job) {
		j, err := s.d.Job(job)
		if err != nil {
			return nil, err
		}
		if j.Dir == "" {
			return nil, status.Error(codes.FailedPrecondition, "el trabajo aún no tiene salidas: ármalo y espera la primera ronda")
		}
		dir = j.Dir
	}
	b, err := analyze.Load(dir)
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, err.Error())
	}
	return b, nil
}

func (s *driftSvc) Drift(_ context.Context, r *v1.DriftRequest) (*v1.DriftResponse, error) {
	s.d.MarkActive()
	b, err := s.bundle(r.Job)
	if err != nil {
		return nil, err
	}
	// device → ronda → running-config
	cfg := map[string]map[int]string{}
	for _, sec := range b.Sections {
		if sec.Invalid || !drift.IsRunningConfig(sec.Command) {
			continue
		}
		if cfg[sec.Device] == nil {
			cfg[sec.Device] = map[int]string{}
		}
		cfg[sec.Device][sec.Round] = sec.Text
	}
	rep := drift.Report{Dir: b.Dir, From: max(int(r.Round)-1, 0), To: int(r.Round), Devices: []drift.DeviceDrift{}, Warnings: []string{}, Masked: masked(b.Dir)}
	for _, w := range b.Warnings {
		rep.Warnings = append(rep.Warnings, strings.Join(nonEmpty(w.Device, w.Command, w.Msg), ": "))
	}
	var names []string
	for dev := range cfg {
		if r.Device == "" || strings.Contains(strings.ToLower(dev), strings.ToLower(r.Device)) {
			names = append(names, dev)
		}
	}
	sort.Strings(names)
	for _, dev := range names {
		var have []int
		for rd := range cfg[dev] {
			have = append(have, rd)
		}
		from, to, ok := drift.Pair(have, int(r.Round))
		if !ok {
			rep.Warnings = append(rep.Warnings, fmt.Sprintf("%s: sin dos rondas con running-config (tiene %v)", dev, have))
			continue
		}
		cs, ign := drift.Compare(cfg[dev][from], cfg[dev][to])
		rep.Devices = append(rep.Devices, drift.NewDevice(dev, from, to, cs, ign))
	}
	if len(rep.Devices) == 0 {
		return nil, status.Error(codes.FailedPrecondition, "ningún equipo tiene dos rondas con show running-config; usa un playbook que lo recolecte y espera la segunda ronda")
	}
	s.d.Audit("drift.run", b.Dir, fmt.Sprintf("ronda=%d equipo=%q equipos=%d", r.Round, r.Device, len(rep.Devices)))
	return &v1.DriftResponse{Report: service.Report(rep, rep.Text())}, nil
}

func nonEmpty(ss ...string) (out []string) {
	for _, s := range ss {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// masked lee del manifest del paquete si Patrol enmascaró secretos. Sin manifest (trabajo en curso o
// carpeta ajena) no se sabe y no se avisa. shortcut: solo el manifest.json suelto, no el de un zip.
func masked(dir string) bool {
	f, err := sys.OpenRegular(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return false
	}
	defer f.Close()
	var m struct {
		Masked bool `json:"masked"`
	}
	return json.NewDecoder(io.LimitReader(f, 8<<20)).Decode(&m) == nil && m.Masked
}

// Module registra el servicio Drift.
type Module struct{}

func (Module) Register(s ipc.Registrar, d service.Deps) {
	v1.RegisterDriftServiceServer(s, &driftSvc{d: d})
}
