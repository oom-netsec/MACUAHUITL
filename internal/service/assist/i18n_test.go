package assist

import (
	"context"
	"errors"
	"strings"
	"testing"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/test/simulator"
)

func info(err error) map[string]string {
	for _, d := range status.Convert(err).Details() {
		if ei, ok := d.(*errdetails.ErrorInfo); ok {
			return map[string]string{"reason": ei.Reason, "template": ei.Metadata["template"], "field": ei.Metadata["field"], "why": ei.Metadata["why"], "device": ei.Metadata["device"], "n": string(rune('0' + len(ei.Metadata)))}
		}
	}
	return nil
}

func TestAssistInvalidValueEnEsYMetadata(t *testing.T) {
	r := newRig(t, simulator.Config{})
	req := tplReq("speed-duplex", map[string]string{"interfaces": gi1, "speed": "9999"})
	req.Target, req.AcceptedHostKeyFingerprints = r.target, []string{r.fp}
	_, es := r.svc.PlanSnippet(context.Background(), req)
	if code(es) != codes.InvalidArgument || !strings.HasPrefix(status.Convert(es).Message(), "assist: valores del snippet inválidos: ") {
		t.Fatalf("es: %v", es)
	}
	_, en := r.svc.PlanSnippet(i18n.WithLocale(context.Background(), "en"), req)
	if m := status.Convert(en).Message(); !strings.HasPrefix(m, "assist: invalid snippet values: speed: ") || strings.Contains(m, "inválid") {
		t.Fatalf("en: %v", en)
	}
	m := info(en)
	if m["reason"] != "assist.invalid_value" || m["template"] != "speed-duplex" || m["field"] != "speed" || m["why"] == "" || m["n"] != "3" {
		t.Fatalf("metadata %v", m)
	}
}

func TestAssistRefusedLlevaPlantillaYEquipo(t *testing.T) {
	r := newRig(t, simulator.Config{Interfaces: map[string][]string{gi1: {"switchport mode trunk"}}})
	req := tplReq("port-security", map[string]string{"interfaces": gi1})
	req.Target, req.AcceptedHostKeyFingerprints = r.target, []string{r.fp}
	_, es := r.svc.PlanSnippet(context.Background(), req)
	_, en := r.svc.PlanSnippet(i18n.WithLocale(context.Background(), "en"), req)
	if code(es) != codes.FailedPrecondition || !strings.HasPrefix(status.Convert(es).Message(), "assist: el equipo no admite este snippet: ") ||
		!strings.HasPrefix(status.Convert(en).Message(), "assist: the device does not support this snippet: ") {
		t.Fatalf("es %v\nen %v", es, en)
	}
	m := info(en)
	if m["reason"] != "assist.refused" || m["template"] == "" || m["device"] == "" || m["n"] != "2" {
		t.Fatalf("metadata %v", m)
	}
}

// La misma plantilla da el mismo `template` (su id del catálogo) en los dos reasons.
func TestTemplateEsElIdDelCatalogoEnAmbosReasons(t *testing.T) {
	r := newRig(t, simulator.Config{Interfaces: map[string][]string{gi1: {"switchport mode trunk"}}})
	tpl := func(vals map[string]string) string {
		req := tplReq("port-security", vals)
		req.Target, req.AcceptedHostKeyFingerprints = r.target, []string{r.fp}
		_, err := r.svc.PlanSnippet(context.Background(), req)
		m := info(err)
		if m == nil {
			t.Fatalf("sin detalles: %v", err)
		}
		return m["reason"] + ":" + m["template"]
	}
	if got := tpl(map[string]string{"interfaces": gi1}); got != "assist.refused:port-security" {
		t.Fatalf("refused: %s", got)
	}
	if got := tpl(map[string]string{"interfaces": gi1, "otro": "x"}); got != "assist.invalid_value:port-security" {
		t.Fatalf("invalid_value: %s", got)
	}
	// Los snippets con formulario propio usan su id del catálogo.
	rv := newRig(t, simulator.Config{Vlans: []int{1, 10}, Commands: map[string]string{"show vtp status": "VTP Domain Name : CAMPUS\nVTP Operating Mode : Server\n"}})
	req := vlanReq(30, "x")
	req.Target, req.AcceptedHostKeyFingerprints = rv.target, []string{rv.fp}
	_, err := rv.svc.PlanSnippet(context.Background(), req)
	if m := info(err); m == nil || m["reason"] != "assist.refused" || m["template"] != "vlan" {
		t.Fatalf("vlan: %v %v", err, m)
	}
}

// Fase 30e: los motivos de la restauración por diff salen en el idioma pedido; con es (o sin idioma) son los de siempre.
func TestPlanRestoreRefusedWhyEsYEn(t *testing.T) {
	r := newRestoreRig(t, restoreRunning, nil)
	id := r.saveBackup(strings.Replace(restoreBackup, "!\nntp server", "!\nvtp mode client\nntp server", 1), false)
	req := &v1.PlanRestoreRequest{Target: r.target, BackupId: id, AcceptedHostKeyFingerprints: []string{r.fp}}
	es, err := r.svc.PlanRestore(context.Background(), req)
	if err != nil || len(es.Refused) != 1 || es.Refused[0].Why != "vtp: se propaga a otros equipos" {
		t.Fatalf("es: %v %+v", err, es)
	}
	en, err := r.svc.PlanRestore(i18n.WithLocale(context.Background(), "en"), req)
	if err != nil || len(en.Refused) != 1 || en.Refused[0].Why != "vtp: it propagates to other devices" || en.Refused[0].Line != es.Refused[0].Line {
		t.Fatalf("en: %v %+v", err, en)
	}
}

// La salida propia de la rotación y los errores del ejecutor salen en el idioma pedido; con es son los de siempre.
func TestRotacionTextosEsYEn(t *testing.T) {
	e := &rotExec{rot: rotation{user: "tech"}}
	tx, err := e.Saved(context.Background(), "SW1")
	if err != nil || tx.In(i18n.Es) != "write memory salió bien; no se indicó credencial de la bóveda que actualizar" ||
		tx.In(i18n.En) != "write memory succeeded; no vault credential to update was given" {
		t.Fatalf("%q %q %v", tx.In(i18n.Es), tx.In(i18n.En), err)
	}
	w := i18n.Wrap("assist.svc.vault_save_new_failed", errors.New("disco lleno"), i18n.A("prev", "lab (anterior)"))
	if w.Error() != `la bóveda no pudo guardar la credencial nueva (la anterior quedó como "lab (anterior)"): disco lleno` ||
		w.Localize(i18n.En) != `the vault could not save the new credential (the previous one was kept as "lab (anterior)"): disco lleno` {
		t.Fatalf("%q %q", w.Error(), w.Localize(i18n.En))
	}
	_, err = (&rotExec{devExec: &devExec{}}).Verify(context.Background(), "nadie")
	var c i18n.Coded
	if !errors.As(err, &c) || c.Reason() != "assist.svc.unknown_device" || c.Localize(i18n.En) != `unknown device "nadie"` || err.Error() != `equipo "nadie" desconocido` {
		t.Fatalf("%v", err)
	}
}
