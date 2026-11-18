package sys

import (
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
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
	var keep []*windows.SID
	for _, s := range sids {
		sid, err := windows.StringToSid(s)
		if err != nil {
			t.Fatal(err)
		}
		keep = append(keep, sid)
		entries = append(entries, windows.EXPLICIT_ACCESS{
			AccessPermissions: fileAllAccess,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
			Trustee:           windows.TRUSTEE{TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeValue: windows.TrusteeValueFromSID(sid)},
		})
	}
	acl, err := windows.ACLFromEntries(entries, nil)
	runtime.KeepAlive(keep)
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
	// En windows-latest el token del runner crea subcarpetas aunque la DACL no dé ADD_SUBDIRECTORY (los archivos sí se
	// niegan). Lo que importa a pack.Install es que nada se escriba dentro: la subcarpeta hereda la solo lectura (OI|CI).
	if p, err := os.MkdirTemp(d, ".t-"); err == nil {
		t.Logf("el token crea subcarpetas sin ADD_SUBDIRECTORY: se comprueba que dentro no se escribe")
		if f, err := os.Create(filepath.Join(p, "x")); err == nil {
			f.Close()
			t.Fatal("se pudo escribir dentro de una subcarpeta de la carpeta de solo lectura")
		}
		restore()
		os.Remove(p)
		restore, _ = ReadOnlyDir(d)
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

func mklinkJunction(t *testing.T, link, target string) {
	t.Helper()
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		t.Skipf("mklink /J no disponible: %v %s", err, out)
	}
}

// Una junction como carpeta de salidas: readACL leería la ACL del destino, así que se rechaza.
func TestPrivateDirYMkdirPrivateRechazanJunction(t *testing.T) {
	base := t.TempDir()
	destino := filepath.Join(base, "destino")
	if err := MkdirPrivate(destino); err != nil {
		t.Fatal(err)
	}
	junction := filepath.Join(base, "j")
	mklinkJunction(t, junction, destino)
	if pe := privateDirReason(t, PrivateDir(junction)); pe.Reason != PrivateDirLink || pe.Path != junction {
		t.Fatalf("PrivateDir = %+v", pe)
	}
	if pe := privateDirReason(t, MkdirPrivate(junction)); pe.Reason != PrivateDirLink {
		t.Fatalf("MkdirPrivate = %+v", pe)
	}
}

func TestMkdirPrivateRechazaRutasRelativasEnWindows(t *testing.T) {
	if err := MkdirPrivate(""); !errors.Is(err, fs.ErrInvalid) {
		t.Fatalf("MkdirPrivate(\"\") = %v", err)
	}
}

// El archivo nace privado: se mira con el handle aún abierto, antes de cualquier ProtectNew.
func TestOpenNewPrivateNaceProtegido(t *testing.T) {
	d := t.TempDir()
	f := filepath.Join(d, "nuevo")
	fh, err := OpenNewPrivate(f)
	if err != nil {
		t.Fatal(err)
	}
	defer fh.Close()
	if ok, err := IsPrivate(f); !ok || err != nil {
		t.Fatalf("IsPrivate = %v, %v", ok, err)
	}
	if _, err := fh.WriteString("x"); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenNewPrivate(f); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("existente: %v", err)
	}
	if _, err := OpenNewPrivate(`\\?\C:\x`); err == nil {
		t.Fatal("aceptó una ruta de dispositivo")
	}
	tmp, err := CreateTempPrivate(d, ".t-*.tmp")
	if err != nil {
		t.Fatal(err)
	}
	tmp.Close()
	if ok, err := IsPrivate(tmp.Name()); !ok || err != nil {
		t.Fatalf("CreateTempPrivate: %v, %v", ok, err)
	}
}

// Lo que llega por red no se desvía: si la carpeta de recepción (ya abierta) se renombra y en su lugar queda una
// junction a otro sitio, OpenNewPrivateIn rechaza y no se escribe nada allá (a lo sumo queda un archivo vacío).
func TestOpenNewPrivateInRechazaCarpetaCambiadaPorJunction(t *testing.T) {
	base := t.TempDir()
	recv, otro := filepath.Join(base, "recv"), filepath.Join(base, "otro")
	for _, d := range []string{recv, otro} {
		if err := MkdirPrivate(d); err != nil {
			t.Fatal(err)
		}
	}
	root, err := os.OpenRoot(recv)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := os.Rename(recv, filepath.Join(base, "recv-movida")); err != nil {
		t.Skipf("no se pudo renombrar la carpeta abierta: %v", err)
	}
	mklinkJunction(t, recv, otro)
	if f, err := OpenNewPrivateIn(root, "x.bat"); err == nil {
		f.Close()
		t.Fatal("OpenNewPrivateIn creó el archivo a través de la junction")
	}
	if fi, err := os.Stat(filepath.Join(otro, "x.bat")); err == nil && fi.Size() != 0 {
		t.Fatalf("se escribió contenido en el destino de la junction (%d bytes)", fi.Size())
	}
}

// 2.3 en Windows de verdad: ForeignWriters ve a Users/Everyone con escritura y no ve la DACL propia ni la de solo lectura.
func TestForeignWritersWindows(t *testing.T) {
	d := filepath.Join(privateTemp(t), "recv")
	if err := MkdirPrivate(d); err != nil {
		t.Fatal(err)
	}
	w, err := ForeignWriters(d)
	if err != nil || len(w.Who) != 0 || w.User != userString(t) {
		t.Fatalf("DACL propia: %+v %v", w, err)
	}
	setDACL(t, d, true, userString(t), sidSystem, sidAdmins, sidTodos)
	if w, err = ForeignWriters(d); err != nil || len(w.Who) != 1 || w.Who[0] != sidTodos {
		t.Fatalf("Everyone con control total: %+v %v", w, err)
	}
}

// 43d-2: la DACL de solo lectura de ReadOnlyDir no cuenta como escritor ajeno; un ACE solo-herencia de Authenticated Users con
// escritura sí (lo que se cree adentro lo hereda); y la carpeta propia en NTFS tiene dueño el usuario.
func TestForeignWritersSoloLecturaYSoloHerencia(t *testing.T) {
	d := filepath.Join(privateTemp(t), "recv")
	if err := MkdirPrivate(d); err != nil {
		t.Fatal(err)
	}
	restore, err := ReadOnlyDir(d)
	if err != nil {
		t.Fatal(err)
	}
	w, err := ForeignWriters(d)
	restore()
	if err != nil || len(w.Who) != 0 || w.ForeignOwner {
		t.Fatalf("solo lectura: %+v %v", w, err)
	}
	const authUsers = "S-1-5-11"
	var entries []windows.EXPLICIT_ACCESS
	var keep []*windows.SID
	for _, s := range []string{userString(t), authUsers} {
		sid, _ := windows.StringToSid(s)
		keep = append(keep, sid)
		inh := uint32(windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT)
		if s == authUsers {
			inh |= 0x8 // INHERIT_ONLY_ACE
		}
		entries = append(entries, windows.EXPLICIT_ACCESS{AccessPermissions: fileAllAccess, AccessMode: windows.GRANT_ACCESS, Inheritance: inh,
			Trustee: windows.TRUSTEE{TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeValue: windows.TrusteeValueFromSID(sid)}})
	}
	acl, err := windows.ACLFromEntries(entries, nil)
	runtime.KeepAlive(keep)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(d, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
	if w, err = ForeignWriters(d); err != nil || len(w.Who) != 1 || w.Who[0] != authUsers {
		t.Fatalf("ACE solo-herencia de Authenticated Users: %+v %v", w, err)
	}
}

// Los SID de protect y ReadOnlyDir viajan en el EXPLICIT_ACCESS como uintptr: el hijo, con GC agresivo y
// GODEBUG=clobberfree=1 (los objetos liberados se rellenan con basura), tiene que ver siempre la DACL correcta.
func TestProtectYReadOnlyDirConGCForzado(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestProtectGCHijo$")
	cmd.Env = append(os.Environ(), "MCTL_SYS_GC_HIJO=1", "GODEBUG=clobberfree=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("hijo: %v\n%s", err, out)
	}
}

func TestProtectGCHijo(t *testing.T) {
	if os.Getenv("MCTL_SYS_GC_HIJO") != "1" {
		t.Skip("solo como hijo de TestProtectYReadOnlyDirConGCForzado")
	}
	defer debug.SetGCPercent(debug.SetGCPercent(1))
	user, err := currentSID()
	if err != nil {
		t.Fatal(err)
	}
	want := user.String()
	for i := 0; i < 200; i++ {
		d := t.TempDir()
		if err := protect(d, true); err != nil {
			t.Fatal(err)
		}
		runtime.GC()
		if ok, err := IsPrivate(d); err != nil || !ok {
			t.Fatalf("vuelta %d: IsPrivate = %v, %v", i, ok, err)
		}
		restore, err := ReadOnlyDir(d)
		if err != nil {
			t.Fatal(err)
		}
		runtime.GC()
		_, _, aces, err := readACL(d)
		if err != nil {
			t.Fatal(err)
		}
		if len(aces) != 1 || aces[0].sid != want {
			t.Fatalf("vuelta %d: ACE = %+v, quiero solo %s", i, aces, want)
		}
		restore()
	}
}
