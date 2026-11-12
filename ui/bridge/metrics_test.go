package bridge

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
)

type fakeMetrics struct {
	v1.UnimplementedMetricsServiceServer
}

func (fakeMetrics) GetJobMetrics(_ context.Context, r *v1.GetJobMetricsRequest) (*v1.GetJobMetricsResponse, error) {
	return &v1.GetJobMetricsResponse{Warnings: []string{"job=" + r.JobId + " dir=" + r.Dir}, Devices: []*v1.DeviceMetrics{{
		Address: "10.0.0.1", Hostname: "SW1", Rounds: 2, InterfaceTotal: 3,
		Cpu:        []*v1.CpuPoint{{Round: 1, AtMs: 1000, FiveSec: 7}},
		Memory:     []*v1.MemorySeries{{Pool: "Processor", Points: []*v1.MemoryPoint{{Round: 1, Used: 4, Free: 6, Total: 10}}}},
		Interfaces: []*v1.InterfaceSeries{{Name: "Gi1/0/1", BwKbit: 1000000, Points: []*v1.InterfacePoint{{Round: 2, InBps: 1e6, Source: "counters", DeltaOk: true, Crc: 4}}}},
		Reboots:    []*v1.RebootEvent{{Round: 2, BootMs: 5}},
	}}}, nil
}

func (fakeMetrics) GetPortStatus(_ context.Context, r *v1.GetPortStatusRequest) (*v1.GetPortStatusResponse, error) {
	src := "live"
	if r.JobId != "" || r.Dir != "" {
		src = "job"
	}
	return &v1.GetPortStatusResponse{Source: src, Address: r.Device, Hostname: "SW1", AtMs: 7, Warnings: []string{"cred=" + r.CredentialId + " job=" + r.JobId + " dir=" + r.Dir},
		Ports:    []*v1.PortInfo{{Name: "Gi1/0/12", Kind: "Gi", Module: 1, Stack: 0, Number: 12, Status: "connected", SpeedMbps: 1000, Trunk: true, Channel: "Po1", ChannelFlags: "P"}},
		Channels: []*v1.PortChannel{{Name: "Po1", State: "SU", Protocol: "LACP", Members: []*v1.ChannelMember{{Port: "Gi1/0/12", Flags: "P"}}}}}, nil
}

func TestMetricsBridge(t *testing.T) {
	d, _ := os.MkdirTemp("", "brg")
	defer os.RemoveAll(d)
	sock := filepath.Join(d, "core.sock")
	l, _ := ipc.Listen(sock)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go ipc.Serve(ctx, l, func(r ipc.Registrar) { v1.RegisterMetricsServiceServer(r, fakeMetrics{}) })
	b := New(func() (*ipc.ClientConn, error) { return ipc.DialPath(sock) }, (&recorder{}).emit)
	Start(ctx, b)
	r, err := b.JobMetrics(MetricsQueryDTO{Job: "abc", Device: "SW1"})
	if err != nil {
		t.Fatal(err)
	}
	if r.Warnings[0] != "job=abc dir=" || len(r.Devices) != 1 || r.Devices[0].CPU[0].FiveSec != 7 || r.Devices[0].Memory[0].Points[0].Total != 10 ||
		r.Devices[0].Interfaces[0].Points[0].CRC != 4 || !r.Devices[0].Interfaces[0].Points[0].DeltaOK || r.Devices[0].Reboots[0].BootMs != 5 {
		t.Fatalf("respuesta = %+v", r)
	}
	// una ruta absoluta viaja como carpeta
	if r, _ = b.JobMetrics(MetricsQueryDTO{Job: "/tmp/trabajo"}); r.Warnings[0] != "job= dir=/tmp/trabajo" {
		t.Fatalf("dir = %v", r.Warnings)
	}
	// las listas vacías viajan como [] y no como null
	j, _ := json.Marshal(JobMetricsDTO{Devices: []DeviceMetricsDTO{}, Warnings: strs(nil)})
	if !strings.Contains(string(j), `"warnings":[]`) {
		t.Fatalf("json = %s", j)
	}
}

func TestPortStatusBridge(t *testing.T) {
	d, _ := os.MkdirTemp("", "brg")
	defer os.RemoveAll(d)
	sock := filepath.Join(d, "core.sock")
	l, _ := ipc.Listen(sock)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go ipc.Serve(ctx, l, func(r ipc.Registrar) { v1.RegisterMetricsServiceServer(r, fakeMetrics{}) })
	b := New(func() (*ipc.ClientConn, error) { return ipc.DialPath(sock) }, (&recorder{}).emit)
	Start(ctx, b)
	r, err := b.PortStatus(PortStatusQueryDTO{Device: "10.0.0.1", CredentialID: "c1"})
	if err != nil || r.Source != "live" || r.Warnings[0] != "cred=c1 job= dir=" {
		t.Fatalf("en vivo: %+v %v", r, err)
	}
	if p := r.Ports[0]; p.Name != "Gi1/0/12" || p.Module != 1 || p.Number != 12 || !p.Trunk || p.Channel != "Po1" || p.SpeedMbps != 1000 || r.Channels[0].Members[0].Flags != "P" {
		t.Fatalf("puerto = %+v", p)
	}
	if r, _ = b.PortStatus(PortStatusQueryDTO{Job: "abc"}); r.Source != "job" || r.Warnings[0] != "cred= job=abc dir=" {
		t.Fatalf("trabajo: %+v", r)
	}
	if r, _ = b.PortStatus(PortStatusQueryDTO{Job: "/tmp/trabajo"}); r.Warnings[0] != "cred= job= dir=/tmp/trabajo" {
		t.Fatalf("carpeta: %+v", r)
	}
}
