package core

import (
	"strings"
	"testing"

	"google.golang.org/grpc/codes"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
)

// hostEn guarda un host de la libreta en el destino del simulador con la plataforma dada.
func (h *harness) hostEn(t *testing.T, name, plat string, cred string) {
	t.Helper()
	inv := v1.NewInventoryServiceClient(h.conn)
	if _, err := inv.PutDevice(ctx(t), &v1.PutDeviceRequest{Device: &v1.Device{Name: name, Target: &v1.Target{Address: h.target.Address},
		Profile: &v1.DeviceProfile{Port: h.target.Port}, Platform: plat, CredentialId: cred}}); err != nil {
		t.Fatal(err)
	}
}

// Un trabajo de cualquier tipo contra un host linux o windows se rechaza al crearlo, con su nombre.
func TestPatrolRechazaHostsGenericos(t *testing.T) {
	for _, plat := range []string{"linux", "windows"} {
		h := newHarness(t, nil)
		cred := h.ready(t)
		h.hostEn(t, "mi-"+plat, plat, "")
		for _, kind := range []string{"", "patrol", "adhoc", "backup", "change"} {
			s := h.spec(cred)
			s.Kind = kind
			_, err := h.patrol.CreateJob(ctx(t), &v1.CreateJobRequest{Spec: s})
			if codeOf(err) != codes.InvalidArgument || !strings.Contains(err.Error(), "mi-"+plat) || !strings.Contains(err.Error(), plat) {
				t.Errorf("%s/%q: %v", plat, kind, err)
			}
		}
	}
	// un host Cisco en esa dirección no estorba
	h := newHarness(t, nil)
	cred := h.ready(t)
	h.hostEn(t, "sw", "ios-xe", "")
	if _, err := h.patrol.CreateJob(ctx(t), &v1.CreateJobRequest{Spec: h.spec(cred)}); err != nil {
		t.Fatal(err)
	}
}

// Una credencial de solo llave (principal, por equipo o de respaldo) se rechaza al crear el trabajo.
func TestPatrolRechazaCredencialesKey(t *testing.T) {
	h := newHarness(t, nil)
	pw := h.ready(t)
	key := h.keygen(t, "llave").Id
	casos := map[string]func(s *v1.JobSpec){
		"principal": func(s *v1.JobSpec) { s.DefaultCredentialId = key },
		"override":  func(s *v1.JobSpec) { s.Overrides = []*v1.DeviceOverride{{DeviceId: "sw1", CredentialId: key}} },
		"respaldo": func(s *v1.JobSpec) {
			s.Overrides = []*v1.DeviceOverride{{DeviceId: "sw1", CredentialId: pw, FallbackCredentialId: key}}
		},
	}
	for n, f := range casos {
		s := h.spec(pw)
		f(s)
		_, err := h.patrol.CreateJob(ctx(t), &v1.CreateJobRequest{Spec: s})
		if codeOf(err) != codes.InvalidArgument || !strings.Contains(err.Error(), "llave") {
			t.Errorf("%s: %v", n, err)
		}
	}
	// y con una contraseña sigue entrando
	if _, err := h.patrol.CreateJob(ctx(t), &v1.CreateJobRequest{Spec: h.spec(pw)}); err != nil {
		t.Fatal(err)
	}
}

// El cambio asistido rechaza al planear un host linux/windows y una credencial key.
func TestAsistidoRechazaGenericosYKey(t *testing.T) {
	h := newHarness(t, nil)
	pw := h.ready(t)
	key := h.keygen(t, "llave").Id
	as := v1.NewAssistServiceClient(h.conn)
	plan := func(cred string) error {
		_, err := as.PlanPorts(ctx(t), &v1.PlanPortsRequest{Target: &v1.AssistTarget{Address: h.target.Address, Port: h.target.Port, CredentialId: cred},
			Interfaces: []string{"GigabitEthernet1/0/1"}, Vlan: 10})
		return err
	}
	if err := plan(key); codeOf(err) != codes.InvalidArgument || !strings.Contains(err.Error(), "llave") {
		t.Errorf("key: %v", err)
	}
	h.hostEn(t, "caja", "windows", "")
	if err := plan(pw); codeOf(err) != codes.InvalidArgument || !strings.Contains(err.Error(), "caja") {
		t.Errorf("host windows: %v", err)
	}
}
