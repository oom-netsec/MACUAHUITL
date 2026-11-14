package i18n

import "testing"

// El aviso de mctl backup collect con el trabajo terminado en error: el español de siempre y su inglés.
func TestMctlBackupJobFailed(t *testing.T) {
	a := A("job", "j1", "error", "boom")
	if got := Msg(Es, "mctl.backup.job_failed", a); got != "el trabajo j1 terminó con error: boom" {
		t.Errorf("es: %q", got)
	}
	if got := Msg(En, "mctl.backup.job_failed", a); got != "job j1 finished with an error: boom" {
		t.Errorf("en: %q", got)
	}
}
