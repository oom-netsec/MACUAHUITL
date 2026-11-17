package sys

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

func TestPrivadasEnLinux(t *testing.T) {
	d := filepath.Join(t.TempDir(), "a", "b")
	if err := MkdirPrivate(d); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(d); fi.Mode().Perm() != 0o700 {
		t.Fatalf("MkdirPrivate dejó %v", fi.Mode().Perm())
	}
	f := filepath.Join(d, "x")
	if err := os.WriteFile(f, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if ok, _ := IsPrivate(f); ok {
		t.Fatal("0644 no es privado")
	}
	if err := ProtectFile(f); err != nil {
		t.Fatal(err)
	}
	if ok, err := IsPrivate(f); !ok || err != nil {
		t.Fatalf("IsPrivate = %v, %v", ok, err)
	}
}

func TestPrivateDirEnLinux(t *testing.T) {
	var pe *PrivateDirError
	t.Setenv("TMPDIR", os.Getenv("HOME")) // /tmp es 1777 y de otro dueño: contaría como ancestro inseguro
	d := filepath.Join(t.TempDir(), "o")
	if err := os.Mkdir(d, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := PrivateDir(d); !errors.As(err, &pe) || pe.Reason != PrivateDirACL {
		t.Fatalf("0755: %v", err)
	}
	if err := os.Chmod(d, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := PrivateDir(d); err != nil {
		t.Fatalf("0700 propia: %v", err)
	}
	if err := PrivateDir(filepath.Join(d, "no")); !errors.As(err, &pe) || pe.Reason != PrivateDirRead {
		t.Fatalf("inexistente: %v", err)
	}
	// /tmp es de otro dueño y 1777: una carpeta suya directo en /tmp se rechaza por ancestro.
	t1, err := os.MkdirTemp("/tmp", "mcw-")
	if err != nil {
		t.Skip(err)
	}
	defer os.RemoveAll(t1)
	if err := PrivateDir(t1); !errors.As(err, &pe) || pe.Reason != PrivateDirAncestor || pe.Path != "/tmp" {
		t.Fatalf("bajo /tmp: %v", err)
	}
}

// ProtectNew no toca el modo en Linux: el archivo ya nació 0600 y un sistema sin permisos no debe fallar.
func TestProtectNewNoHaceNadaEnLinux(t *testing.T) {
	f := filepath.Join(t.TempDir(), "x")
	if err := os.WriteFile(f, nil, 0o640); err != nil {
		t.Fatal(err)
	}
	os.Chmod(f, 0o640)
	if err := ProtectNew(f); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(f); fi.Mode().Perm() != 0o640 {
		t.Fatalf("modo %v", fi.Mode().Perm())
	}
}

func TestReadOnlyDirEnLinux(t *testing.T) {
	d := t.TempDir()
	antes, _ := os.Stat(d)
	restore, err := ReadOnlyDir(d)
	if err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(d); fi.Mode().Perm() != 0o500 {
		t.Fatalf("modo %v", fi.Mode().Perm())
	}
	restore()
	if fi, _ := os.Stat(d); fi.Mode().Perm() != antes.Mode().Perm() {
		t.Fatalf("restaurado %v", fi.Mode().Perm())
	}
}

func TestMkdirPrivateRechazaRutasRelativas(t *testing.T) {
	t.Chdir(t.TempDir())
	for _, p := range []string{"", "rel", "./rel"} {
		if err := MkdirPrivate(p); !errors.Is(err, fs.ErrInvalid) {
			t.Errorf("MkdirPrivate(%q) = %v", p, err)
		}
	}
	if es, _ := os.ReadDir("."); len(es) != 0 {
		t.Fatalf("creó algo en el directorio actual: %v", es)
	}
}

func TestOpenNewPrivateYCreateTempPrivateEnLinux(t *testing.T) {
	d := t.TempDir()
	f, err := OpenNewPrivate(filepath.Join(d, "a"))
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if ok, _ := IsPrivate(filepath.Join(d, "a")); !ok {
		t.Fatal("OpenNewPrivate no dejó 0600")
	}
	if _, err := OpenNewPrivate(filepath.Join(d, "a")); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("segunda vez: %v", err)
	}
	tmp, err := CreateTempPrivate(d, ".x-*.tmp")
	if err != nil {
		t.Fatal(err)
	}
	tmp.Close()
	if ok, _ := IsPrivate(tmp.Name()); !ok {
		t.Fatal("CreateTempPrivate no dejó 0600")
	}
}

// fijaGrupo apunta /etc/group y /etc/passwd a archivos de prueba y hace que el usuario sea el gid de la carpeta d (uid = gid = el de d).
func fijaGrupo(t *testing.T, d, group, passwd string) {
	t.Helper()
	gid := mustStat(t, d).Gid
	dir := t.TempDir()
	oldG, oldP, oldE, oldGid, oldACL := groupFile, passwdFile, geteuid, getegid, hasPosixACL
	groupFile, passwdFile = filepath.Join(dir, "group"), filepath.Join(dir, "passwd")
	if group != "-" {
		os.WriteFile(groupFile, []byte(strings.ReplaceAll(group, "GID", strconv.Itoa(int(gid)))), 0o600)
	}
	if passwd != "-" {
		os.WriteFile(passwdFile, []byte(strings.ReplaceAll(passwd, "GID", strconv.Itoa(int(gid)))), 0o600)
	}
	geteuid, getegid = func() uint32 { return gid }, func() uint32 { return gid }
	hasPosixACL = func(*os.File) bool { return false }
	t.Cleanup(func() { groupFile, passwdFile, geteuid, getegid, hasPosixACL = oldG, oldP, oldE, oldGid, oldACL })
}

func mustStat(t *testing.T, d string) *syscall.Stat_t {
	t.Helper()
	fi, err := os.Stat(d)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Sys().(*syscall.Stat_t)
}

// R1: g+w se ignora solo si el grupo es el privado del usuario Y no tiene otros miembros; el bit de otros siempre cuenta.
// Prueba la función REAL con /etc/group y /etc/passwd de prueba.
func TestForeignWritersBitsDeGrupoYOtros(t *testing.T) {
	gid := int(mustStat(t, t.TempDir()).Gid)
	uid := gid
	for _, c := range []struct {
		nombre        string
		modo          os.FileMode
		group, passwd string
		acl           bool
		want          []string
	}{
		{"privado", 0o770, "yo:x:GID:\n", "yo:x:UID:GID::/:/bin/sh\n", false, nil},
		{"0700", 0o700, "yo:x:GID:\n", "yo:x:UID:GID::/:/bin/sh\n", false, nil},
		{"miembro suplementario", 0o770, "yo:x:GID:otro\n", "yo:x:UID:GID::/:/bin/sh\n", false, []string{"g+w"}},
		{"otro con ese grupo primario", 0o770, "yo:x:GID:\n", "yo:x:UID:GID::/:/bin/sh\notro:x:9999:GID::/:/bin/sh\n", false, []string{"g+w"}},
		{"grupo no listado (NSS)", 0o770, "x:x:5555:\n", "yo:x:UID:GID::/:/bin/sh\n", false, []string{"g+w"}},
		{"sin /etc/group", 0o770, "-", "yo:x:UID:GID::/:/bin/sh\n", false, []string{"g+w"}},
		{"sin /etc/passwd", 0o770, "yo:x:GID:\n", "-", false, []string{"g+w"}},
		{"con ACL POSIX", 0o770, "yo:x:GID:\n", "yo:x:UID:GID::/:/bin/sh\n", true, []string{"g+w"}},
		{"otros siempre", 0o707, "yo:x:GID:\n", "yo:x:UID:GID::/:/bin/sh\n", false, []string{"o+w"}},
		{"compartido y otros", 0o777, "yo:x:GID:otro\n", "yo:x:UID:GID::/:/bin/sh\n", false, []string{"g+w", "o+w"}},
	} {
		d := t.TempDir()
		os.Chmod(d, c.modo)
		fijaGrupo(t, d, c.group, strings.ReplaceAll(c.passwd, "UID", strconv.Itoa(uid)))
		if c.acl {
			hasPosixACL = func(*os.File) bool { return true }
		}
		w, err := ForeignWriters(d)
		who := slices.DeleteFunc(w.Who, func(x string) bool { return x == "owner" }) // el uid simulado no es el dueño real
		if err != nil || !slices.Equal(who, c.want) {
			t.Errorf("%s: %v %v, quería %v", c.nombre, w.Who, err, c.want)
		}
	}
}

// El grupo de la carpeta distinto del gid del usuario nunca es privado.
func TestForeignWritersGrupoAjeno(t *testing.T) {
	d := t.TempDir()
	os.Chmod(d, 0o770)
	fijaGrupo(t, d, "yo:x:GID:\n", "-")
	getegid = func() uint32 { return mustStat(t, d).Gid + 1 }
	if w, _ := ForeignWriters(d); !slices.Equal(w.Who, []string{"g+w"}) {
		t.Errorf("%v", w.Who)
	}
}

// M3: un dueño que no es el usuario se cuenta («owner», sin orden posible).
func TestForeignWritersDuenoAjeno(t *testing.T) {
	d := t.TempDir()
	fijaGrupo(t, d, "yo:x:GID:\n", "-")
	geteuid = func() uint32 { return mustStat(t, d).Uid + 1 }
	w, err := ForeignWriters(d)
	if err != nil || !w.ForeignOwner || !slices.Contains(w.Who, "owner") {
		t.Errorf("%+v %v", w, err)
	}
}

// En un volumen común el xattr del ACL POSIX no existe (o no hay soporte): no cuenta como ACL.
func TestHasPosixACLRealSinACL(t *testing.T) {
	f, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if hasPosixACL(f) {
		t.Error("una carpeta nueva no lleva ACL POSIX")
	}
}

// R2: ntfs-3g sin «permissions» (fuseblk sin default_permissions) no tiene permisos por usuario; con ellas, sí; otros sistemas, sí.
func TestNoPermsFuse(t *testing.T) {
	const dev = 8<<8 | 1 // 8:1
	for _, c := range []struct {
		linea string
		want  bool
	}{
		{"40 25 8:1 / /mnt rw - fuseblk /dev/sda1 rw,user_id=0,group_id=0,allow_other,blksize=4096", true},
		{"40 25 8:1 / /mnt rw - fuseblk /dev/sda1 rw,user_id=0,group_id=0,default_permissions,allow_other", false},
		{"40 25 8:1 / /mnt rw - fuse.ntfs-3g /dev/sda1 rw,user_id=0", true},
		{"40 25 8:1 / /mnt rw - fuse.sshfs u@h:/ rw,user_id=0", false},
		{"40 25 8:2 / /mnt rw - fuseblk /dev/sda2 rw", false}, // otro dispositivo
	} {
		if got := noPermsFuse(c.linea+"\n", dev); got != c.want {
			t.Errorf("%q: %v", c.linea, got)
		}
	}
}
