package bridge

import (
	"context"
	"fmt"
	"io"
	"path/filepath"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
)

// ---- Visibilidad (topología, SNMP, traps, flujos, gNMI) ----

type TopoDTO struct {
	Text string `json:"text"`
	Json string `json:"json"`
	Svg  string `json:"svg"`
}

// TopoBuild acepta un ID de trabajo o una carpeta de salida absoluta, y/o una captura.
func (b *Bridge) TopoBuild(jobOrDir, pcap string) (TopoDTO, error) {
	req := &v1.BuildTopologyRequest{PcapPath: pcap}
	if filepath.IsAbs(jobOrDir) {
		req.Dir = jobOrDir
	} else {
		req.JobId = jobOrDir
	}
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (TopoDTO, error) {
		r, err := v1.NewVisibilityServiceClient(c).BuildTopology(ctx, req)
		return TopoDTO{Text: r.GetReport().GetText(), Json: r.GetReport().GetJson(), Svg: r.GetSvg()}, err
	})
}

// SnmpTargetDTO nunca trae secretos: solo el ID de la credencial en la bóveda.
type SnmpTargetDTO struct {
	Host         string `json:"host"`
	Port         int    `json:"port"`
	Version      string `json:"version"`
	CredentialId string `json:"credentialId"`
	Auth         string `json:"auth"`
	Priv         string `json:"priv"`
}

func (t SnmpTargetDTO) proto() (*v1.SnmpTarget, error) {
	if t.Port < 0 || t.Port > 65535 {
		return nil, fmt.Errorf("puerto %d inválido", t.Port)
	}
	return &v1.SnmpTarget{Host: t.Host, Port: uint32(t.Port), Version: t.Version, CredentialId: t.CredentialId, AuthProtocol: t.Auth, PrivProtocol: t.Priv}, nil
}

func (b *Bridge) SnmpGet(t SnmpTargetDTO, oids []string) (string, error) {
	pt, err := t.proto()
	if err != nil {
		return "", err
	}
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (string, error) {
		r, err := v1.NewVisibilityServiceClient(c).SnmpGet(ctx, &v1.SnmpGetRequest{Target: pt, Oids: oids})
		return r.GetReport().GetText(), err
	})
}

func (b *Bridge) SnmpWalk(t SnmpTargetDTO, oid string, bulk bool) (string, error) {
	pt, err := t.proto()
	if err != nil {
		return "", err
	}
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (string, error) {
		r, err := v1.NewVisibilityServiceClient(c).SnmpWalk(ctx, &v1.SnmpWalkRequest{Target: pt, Oid: oid, Bulk: bulk})
		return r.GetReport().GetText(), err
	})
}

// stream abre un RPC de servidor y reenvía cada respuesta como <name>:msg {runId, ...}
// y el cierre como <name>:done {runId, error?}. Se detiene con DiagCancel(id).
func (b *Bridge) stream(name string, open func(ctx context.Context, c *ipc.ClientConn) (func() (map[string]any, error), error)) (string, error) {
	c, err := b.client()
	if err != nil {
		return "", err
	}
	b.mu.Lock()
	b.runSeq++
	id := fmt.Sprintf("run-%d", b.runSeq)
	ctx, cancel := context.WithCancel(b.ctx)
	b.runs[id] = cancel
	b.mu.Unlock()
	recv, err := open(ctx, c)
	if err != nil {
		b.mu.Lock()
		delete(b.runs, id)
		b.mu.Unlock()
		cancel()
		return "", err
	}
	go func() {
		defer func() {
			b.mu.Lock()
			delete(b.runs, id)
			b.mu.Unlock()
			cancel()
		}()
		for {
			ev, err := recv()
			if err != nil {
				done := map[string]any{"runId": id}
				if ctx.Err() == nil && err != io.EOF {
					done["error"] = err.Error()
				}
				b.emit(name+":done", done)
				return
			}
			ev["runId"] = id
			b.emit(name+":msg", ev)
		}
	}()
	return id, nil
}

// SnmpPollStart emite snmp:msg {runId, json} por muestra.
func (b *Bridge) SnmpPollStart(t SnmpTargetDTO, profiles []string, every int) (string, error) {
	pt, err := t.proto()
	if err != nil {
		return "", err
	}
	return b.stream("snmp", func(ctx context.Context, c *ipc.ClientConn) (func() (map[string]any, error), error) {
		st, err := v1.NewVisibilityServiceClient(c).SnmpPoll(ctx, &v1.SnmpPollRequest{Target: pt, Profiles: profiles, IntervalSeconds: int32(every)})
		if err != nil {
			return nil, err
		}
		return func() (map[string]any, error) {
			r, err := st.Recv()
			return map[string]any{"json": r.GetJson()}, err
		}, nil
	})
}

// TrapsStart emite traps:msg {runId, listening?, outputPath?, json?, rotatedPath?, drops?}; con save,
// outputPath es la carpeta y rotatedPath cada archivo nuevo. Topes y archivo, como en SyslogStart.
func (b *Bridge) TrapsStart(addr string, allowAny, save bool, v3Cred, auth, priv string, o SyslogOptions) (string, error) {
	if err := o.check(); err != nil {
		return "", err
	}
	return b.stream("traps", func(ctx context.Context, c *ipc.ClientConn) (func() (map[string]any, error), error) {
		st, err := v1.NewVisibilityServiceClient(c).SnmpTraps(ctx, &v1.SnmpTrapsRequest{Addr: addr, AllowAny: allowAny, Save: save, V3CredentialId: v3Cred, AuthProtocol: auth, PrivProtocol: priv,
			RatePerSource: int32(o.RatePerSource), BurstPerSource: int32(o.BurstPerSource), RateGlobal: int32(o.RateGlobal), BurstGlobal: int32(o.BurstGlobal), QueueSize: int32(o.QueueSize),
			RotateMb: int32(o.RotateMB), RotateMinutes: int32(o.RotateMinutes), NameTemplate: o.NameTemplate, MaxFiles: int32(o.MaxFiles), Format: o.Format})
		if err != nil {
			return nil, err
		}
		return func() (map[string]any, error) {
			r, err := st.Recv()
			ev := map[string]any{"listening": r.GetListening(), "outputPath": r.GetOutputPath(), "json": r.GetJson(), "rotatedPath": r.GetRotatedPath()}
			if d := r.GetDrops(); d != nil {
				ev["drops"] = dropsDTO(d)
			}
			return ev, err
		}, nil
	})
}

// FlowsStart emite flows:msg {runId, listening?, outputPath?, json?, final?, rotatedPath?, drops?}.
// Los topes de tasa cuentan datagramas de exportación y solo rigen con save (defaults 1000/s por exportador y 5000/s global).
func (b *Bridge) FlowsStart(addr string, allowAny, save bool, top int, o SyslogOptions) (string, error) {
	if int(int32(top)) != top { // el proto es int32: no se trunca en silencio
		return "", fmt.Errorf("top fuera de rango: %d", top)
	}
	if err := o.check(); err != nil {
		return "", err
	}
	return b.stream("flows", func(ctx context.Context, c *ipc.ClientConn) (func() (map[string]any, error), error) {
		st, err := v1.NewVisibilityServiceClient(c).Flows(ctx, &v1.FlowsRequest{Addr: addr, AllowAny: allowAny, Save: save, Top: int32(top),
			RatePerSource: int32(o.RatePerSource), BurstPerSource: int32(o.BurstPerSource), RateGlobal: int32(o.RateGlobal), BurstGlobal: int32(o.BurstGlobal), QueueSize: int32(o.QueueSize),
			RotateMb: int32(o.RotateMB), RotateMinutes: int32(o.RotateMinutes), NameTemplate: o.NameTemplate, MaxFiles: int32(o.MaxFiles), Format: o.Format})
		if err != nil {
			return nil, err
		}
		return func() (map[string]any, error) {
			r, err := st.Recv()
			ev := map[string]any{"listening": r.GetListening(), "outputPath": r.GetOutputPath(), "json": r.GetJson(), "final": r.GetFinal(), "rotatedPath": r.GetRotatedPath()}
			if d := r.GetDrops(); d != nil {
				ev["drops"] = dropsDTO(d)
			}
			return ev, err
		}, nil
	})
}

type GnmiTargetDTO struct {
	Host         string `json:"host"`
	Port         int    `json:"port"`
	CredentialId string `json:"credentialId"`
	CaPath       string `json:"caPath"`
	ServerName   string `json:"serverName"`
}

func (t GnmiTargetDTO) proto() (*v1.GnmiTarget, error) {
	if t.Port < 0 || t.Port > 65535 {
		return nil, fmt.Errorf("puerto %d inválido", t.Port)
	}
	return &v1.GnmiTarget{Host: t.Host, Port: uint32(t.Port), CredentialId: t.CredentialId, CaPath: t.CaPath, ServerName: t.ServerName}, nil
}

func (b *Bridge) GnmiGet(t GnmiTargetDTO, paths []string, encoding string) (string, error) {
	pt, err := t.proto()
	if err != nil {
		return "", err
	}
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (string, error) {
		r, err := v1.NewVisibilityServiceClient(c).GnmiGet(ctx, &v1.GnmiGetRequest{Target: pt, Paths: paths, Encoding: encoding})
		return r.GetReport().GetText(), err
	})
}

// GnmiSubscribeStart emite gnmi:msg {runId, json} por actualización.
func (b *Bridge) GnmiSubscribeStart(t GnmiTargetDTO, paths []string, mode string, every int) (string, error) {
	pt, err := t.proto()
	if err != nil {
		return "", err
	}
	return b.stream("gnmi", func(ctx context.Context, c *ipc.ClientConn) (func() (map[string]any, error), error) {
		st, err := v1.NewVisibilityServiceClient(c).GnmiSubscribe(ctx, &v1.GnmiSubscribeRequest{Target: pt, Paths: paths, Mode: mode, IntervalSeconds: int32(every)})
		if err != nil {
			return nil, err
		}
		return func() (map[string]any, error) {
			r, err := st.Recv()
			return map[string]any{"json": r.GetJson()}, err
		}, nil
	})
}
