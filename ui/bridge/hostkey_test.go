package bridge

import (
	"context"
	"sync"
	"testing"
	"time"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
)

// Huellas atadas al equipo: cada llamada del puente debe pasar los pares (host, huella) al campo accepted_host_keys.

var keysIn = []AcceptedHostKeyDTO{{Host: "10.0.0.1", Fingerprint: "SHA256:a"}, {Host: "sw2.lab:2222", Fingerprint: "SHA256:b"}}

func keysOK(t *testing.T, who string, got []*v1.AcceptedHostKey) {
	t.Helper()
	if len(got) != 2 || got[0].Host != "10.0.0.1" || got[0].Fingerprint != "SHA256:a" || got[1].Host != "sw2.lab:2222" || got[1].Fingerprint != "SHA256:b" {
		t.Errorf("%s: acceptedHostKeys = %v", who, got)
	}
}

type hkFake struct {
	mu   sync.Mutex
	keys map[string][]*v1.AcceptedHostKey
}

func (f *hkFake) put(k string, v []*v1.AcceptedHostKey) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.keys == nil {
		f.keys = map[string][]*v1.AcceptedHostKey{}
	}
	f.keys[k] = v
}

type hkAdhoc struct {
	v1.UnimplementedAdhocServiceServer
	f *hkFake
}

func (s hkAdhoc) StartAdhoc(_ context.Context, r *v1.StartAdhocRequest) (*v1.StartAdhocResponse, error) {
	s.f.put("adhoc", r.AcceptedHostKeys)
	return &v1.StartAdhocResponse{}, nil
}

type hkBackup struct {
	v1.UnimplementedBackupServiceServer
	f *hkFake
}

func (s hkBackup) StartBackup(_ context.Context, r *v1.StartBackupRequest) (*v1.StartBackupResponse, error) {
	s.f.put("backup", r.AcceptedHostKeys)
	return &v1.StartBackupResponse{}, nil
}

type hkChange struct {
	v1.UnimplementedChangeServiceServer
	f *hkFake
}

func (s hkChange) CaptureChange(_ context.Context, r *v1.CaptureChangeRequest) (*v1.CaptureChangeResponse, error) {
	s.f.put("change", r.AcceptedHostKeys)
	return &v1.CaptureChangeResponse{}, nil
}

type hkPatrol struct {
	v1.UnimplementedPatrolServiceServer
	f *hkFake
}

func (s hkPatrol) ArmJob(_ context.Context, r *v1.ArmJobRequest) (*v1.ArmJobResponse, error) {
	s.f.put("arm", r.AcceptedHostKeys)
	return &v1.ArmJobResponse{}, nil
}

type hkMetrics struct {
	v1.UnimplementedMetricsServiceServer
	f *hkFake
}

func (s hkMetrics) GetPortStatus(_ context.Context, r *v1.GetPortStatusRequest) (*v1.GetPortStatusResponse, error) {
	s.f.put("ports", r.AcceptedHostKeys)
	return &v1.GetPortStatusResponse{}, nil
}

type hkTransfer struct {
	v1.UnimplementedTransferServiceServer
	f *hkFake
}

func (s hkTransfer) Get(_ context.Context, r *v1.GetRequest) (*v1.GetResponse, error) {
	s.f.put("get", r.AcceptedHostKeys)
	return &v1.GetResponse{}, nil
}
func (s hkTransfer) Put(_ context.Context, r *v1.PutRequest) (*v1.PutResponse, error) {
	s.f.put("put", r.AcceptedHostKeys)
	return &v1.PutResponse{}, nil
}
func (s hkTransfer) Browse(_ context.Context, r *v1.BrowseRequest) (*v1.BrowseResponse, error) {
	s.f.put("browse", r.AcceptedHostKeys)
	return &v1.BrowseResponse{}, nil
}
func (s hkTransfer) GetStream(r *v1.GetStreamRequest, _ v1.TransferService_GetStreamServer) error {
	s.f.put("getstream", r.Request.AcceptedHostKeys)
	return nil
}
func (s hkTransfer) PutStream(r *v1.PutStreamRequest, _ v1.TransferService_PutStreamServer) error {
	s.f.put("putstream", r.Request.AcceptedHostKeys)
	return nil
}
func (s hkTransfer) GetMany(r *v1.GetManyRequest, _ v1.TransferService_GetManyServer) error {
	s.f.put("getmany", r.AcceptedHostKeys)
	return nil
}

type hkTerminal struct {
	v1.UnimplementedTerminalServiceServer
	f *hkFake
}

func (s hkTerminal) OpenTerminal(st v1.TerminalService_OpenTerminalServer) error {
	m, _ := st.Recv()
	s.f.put("terminal", m.GetOpen().AcceptedHostKeys)
	return nil
}

func TestHostKeysPorHost(t *testing.T) {
	f := &hkFake{}
	b, _ := startServices(t, func(r ipc.Registrar) {
		v1.RegisterAdhocServiceServer(r, hkAdhoc{f: f})
		v1.RegisterBackupServiceServer(r, hkBackup{f: f})
		v1.RegisterChangeServiceServer(r, hkChange{f: f})
		v1.RegisterPatrolServiceServer(r, hkPatrol{f: f})
		v1.RegisterMetricsServiceServer(r, hkMetrics{f: f})
		v1.RegisterTransferServiceServer(r, hkTransfer{f: f})
		v1.RegisterTerminalServiceServer(r, hkTerminal{f: f})
	})
	tg := []AdhocTargetDTO{{Address: "10.0.0.1"}, {Address: "sw2.lab", Port: 2222}}
	b.AdhocStart(tg, "c", "show clock", nil, keysIn)
	b.BackupStart(tg, "c", true, 1, 0, 0, false, nil, keysIn, "")
	b.ChangeCapture("ch", "pre", nil, keysIn, nil)
	b.ArmJob("j", nil, keysIn, nil)
	b.PortStatus(PortStatusQueryDTO{Device: "10.0.0.1", AcceptedKeys: keysIn})
	b.TransferGet(TransferGetDTO{URL: "sftp://h/x", AcceptedKeys: keysIn})
	b.TransferPut(TransferPutDTO{URL: "sftp://h/x", AcceptedKeys: keysIn})
	b.TransferBrowse(TransferBrowseDTO{URL: "sftp://h/", AcceptedKeys: keysIn})
	b.TransferGetAsync(TransferGetDTO{URL: "sftp://h/x", AcceptedKeys: keysIn})
	b.TransferPutAsync(TransferPutDTO{URL: "sftp://h/x", AcceptedKeys: keysIn})
	b.TransferGetMany(TransferGetManyDTO{URL: "sftp://h/", Names: []string{"a"}, AcceptedKeys: keysIn})
	b.TerminalOpen(TerminalDTO{Address: "10.0.0.1", AcceptedKeys: keysIn})
	for _, k := range []string{"adhoc", "backup", "change", "arm", "ports", "get", "put", "browse", "getstream", "putstream", "getmany", "terminal"} {
		// Las llamadas en segundo plano (stream) llegan un instante después.
		waitKeys(t, f, k)
		f.mu.Lock()
		keysOK(t, k, f.keys[k])
		f.mu.Unlock()
	}
}

func waitKeys(t *testing.T, f *hkFake, k string) {
	t.Helper()
	for i := 0; i < 200; i++ {
		f.mu.Lock()
		_, ok := f.keys[k]
		f.mu.Unlock()
		if ok {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Errorf("%s: la llamada no llegó al núcleo", k)
}
