package sys

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

const (
	sidUsuarios = "S-1-5-32-545"
	sidTodos    = "S-1-1-0"
)

// setDACL reemplaza la DACL de path por una explícita con los SID dados (acceso total, heredable) y sin tocar el dueño.
func setDACL(t *testing.T, path string, protected bool, sids ...string) {
	t.Helper()
	var entries []windows.EXPLICIT_ACCESS
	for _, s := range sids {
		sid, err := windows.StringToSid(s)
		if err != nil {
			t.Fatal(err)
		}
		entries = append(entries, windows.EXPLICIT_ACCESS{
			AccessPermissions: fileAllAccess,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
			Trustee:           windows.TRUSTEE{TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeValue: windows.TrusteeValueFromSID(sid)},
		})
	}
	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		t.Fatal(err)
	}
	info := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION)
	if protected {
		info |= windows.PROTECTED_DACL_SECURITY_INFORMATION
	} else {
		info |= windows.UNPROTECTED_DACL_SECURITY_INFORMATION
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, info, nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
}

func userString(t *testing.T) string {
	t.Helper()
	u, err := currentSID()
	if err != nil {
		t.Fatal(err)
	}
	return u.String()
}

func privateDirReason(t *testing.T, err error) *PrivateDirError {
	t.Helper()
	var pe *PrivateDirError
	if !errors.As(err, &pe) {
		t.Fatalf("se esperaba PrivateDirError, vino %v", err)
	}
	return pe
}

func TestPrivateDirRechazaUsuarios(t *testing.T) {
	d := filepath.Join(t.TempDir(), "o")
	if err := MkdirPrivate(d); err != nil {
		t.Fatal(err)
	}
	setDACL(t, d, true, userString(t), sidSystem, sidAdmins, sidUsuarios)
	pe := privateDirReason(t, PrivateDir(d))
	if pe.Reason != PrivateDirACL || pe.SID != sidUsuarios || pe.Path != d {
		t.Fatalf("PrivateDir = %+v", pe)
	}
}

func TestPrivateDirAceptaDACLPropia(t *testing.T) {
	d := filepath.Join(t.TempDir(), "o")
	if err := MkdirPrivate(d); err != nil {
		t.Fatal(err)
	}
	if err := PrivateDir(d); err != nil {
		t.Fatalf("PrivateDir: %v", err)
	}
}

func TestPrivateDirRechazaAncestorEscribibleParaTodos(t *testing.T) {
	padre := filepath.Join(t.TempDir(), "padre")
	if err := os.Mkdir(padre, 0o700); err != nil {
		t.Fatal(err)
	}
	setDACL(t, padre, true, userString(t), sidSystem, sidAdmins, sidTodos)
	d := filepath.Join(padre, "o")
	if err := MkdirPrivate(d); err != nil {
		t.Fatal(err)
	}
	pe := privateDirReason(t, PrivateDir(d))
	if pe.Reason != PrivateDirAncestor || pe.Path != padre || pe.SID != sidTodos {
		t.Fatalf("PrivateDir = %+v", pe)
	}
}

func TestMkdirPrivateReaplicaSobreCarpetaPropiaConACLHeredada(t *testing.T) {
	d := filepath.Join(t.TempDir(), "config")
	if err := os.Mkdir(d, 0o700); err != nil {
		t.Fatal(err)
	}
	// Como la deja la UI: heredada del padre (aquí, con Usuarios dentro).
	setDACL(t, d, false, userString(t), sidSystem, sidAdmins, sidUsuarios)
	if ok, err := IsPrivate(d); ok || err != nil {
		t.Fatalf("antes: IsPrivate = %v, %v", ok, err)
	}
	if err := MkdirPrivate(filepath.Join(d, "sub", "hondo")); err != nil {
		t.Fatal(err)
	}
	if err := MkdirPrivate(d); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{d, filepath.Join(d, "sub"), filepath.Join(d, "sub", "hondo")} {
		if ok, err := IsPrivate(p); !ok || err != nil {
			t.Errorf("%s: IsPrivate = %v, %v", p, ok, err)
		}
	}
	// Lo que se cree adentro hereda la DACL: sin SID ajeno.
	f := filepath.Join(d, "x.db")
	if err := os.WriteFile(f, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, aces, err := readACL(f)
	if err != nil {
		t.Fatal(err)
	}
	if sid := foreignSID(aces, userString(t), anyAccess, false); sid != "" {
		t.Fatalf("el archivo hereda acceso de %s", sid)
	}
}

func TestMkdirPrivateRechazaCarpetaDeOtroDueno(t *testing.T) {
	// %SystemRoot% es de TrustedInstaller y siempre existe: no se modifica nada.
	err := MkdirPrivate(os.Getenv("SystemRoot"))
	var e *i18n.Error
	if !errors.As(err, &e) || e.Code != "sys.err.not_owner" {
		t.Fatalf("MkdirPrivate = %v", err)
	}
}

func TestProtectFileSoloUsuarioSystemYAdministradores(t *testing.T) {
	f := filepath.Join(t.TempDir(), "secreto")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ProtectFile(f); err != nil {
		t.Fatal(err)
	}
	if ok, err := IsPrivate(f); !ok || err != nil {
		t.Fatalf("IsPrivate = %v, %v", ok, err)
	}
	if b, err := os.ReadFile(f); err != nil || string(b) != "x" {
		t.Fatalf("el dueño ya no lee su archivo: %q, %v", b, err)
	}
	_, protected, aces, err := readACL(f)
	if err != nil || !protected || len(aces) != 3 {
		t.Fatalf("protected=%v aces=%v err=%v", protected, aces, err)
	}
}

// Una DACL protegida con un tercero no es privada: IsPrivate no se conforma con el dueño.
func TestIsPrivateRechazaTerceros(t *testing.T) {
	f := filepath.Join(t.TempDir(), "x")
	if err := os.WriteFile(f, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	setDACL(t, f, true, userString(t), sidSystem, sidAdmins, sidUsuarios)
	if ok, err := IsPrivate(f); ok || err != nil {
		t.Fatalf("IsPrivate = %v, %v", ok, err)
	}
}

func TestProtectNewDejaElArchivoPrivadoAntesDeEscribir(t *testing.T) {
	f := filepath.Join(t.TempDir(), "nuevo")
	fh, err := os.OpenFile(f, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer fh.Close()
	if err := ProtectNewStrict(f); err != nil {
		t.Fatal(err)
	}
	if _, err := fh.WriteString("secreto"); err != nil { // el handle abierto sigue valiendo
		t.Fatal(err)
	}
	if ok, err := IsPrivate(f); !ok || err != nil {
		t.Fatalf("IsPrivate = %v, %v", ok, err)
	}
}

// OnlyOwnAccess acepta una DACL heredada (sin proteger) con solo los tres SID y rechaza la que trae a un tercero.
func TestOnlyOwnAccess(t *testing.T) {
	f := filepath.Join(t.TempDir(), "x")
	if err := os.WriteFile(f, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	setDACL(t, f, false, userString(t), sidSystem, sidAdmins)
	if ok, err := OnlyOwnAccess(f); !ok || err != nil {
		t.Fatalf("propias: %v, %v", ok, err)
	}
	setDACL(t, f, false, userString(t), sidSystem, sidAdmins, sidUsuarios)
	if ok, err := OnlyOwnAccess(f); ok || err != nil {
		t.Fatalf("con Usuarios: %v, %v", ok, err)
	}
}

func TestReadOnlyDirNiegaCrearYSeRestaura(t *testing.T) {
	d := privateTemp(t)
	restore, err := ReadOnlyDir(d)
	if err != nil {
		t.Fatal(err)
	}
	if f, err := os.Create(filepath.Join(d, "x")); err == nil {
		f.Close()
		t.Fatal("se pudo crear un archivo en la carpeta de solo lectura")
	}
	restore()
	f, err := os.Create(filepath.Join(d, "x"))
	if err != nil {
		t.Fatalf("tras restaurar: %v", err)
	}
	f.Close()
}

func privateTemp(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	if err := MkdirPrivate(d); err != nil {
		t.Fatal(err)
	}
	return d
}
