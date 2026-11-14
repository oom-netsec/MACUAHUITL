package fileserve

import (
	"bytes"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/sys"
)

func TestValidateDir(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", "")
	for _, sub := range []string{".ssh", ".gnupg", ".aws", ".config/macuahuitl", ".local/share/macuahuitl/sub"} {
		os.MkdirAll(filepath.Join(home, sub), 0o700)
	}
	ok := t.TempDir()
	if got, err := ValidateDir(ok); err != nil || got != ok {
		t.Fatalf("carpeta normal: %q %v", got, err)
	}
	// Sensibles: exactas y lo que cuelga de ellas.
	bad := []string{"/", "/etc", "/etc/ssh", "/usr", "/usr/share", "/bin", "/boot", "/proc", "/sys", "/dev", "/proc/self",
		filepath.Join(home, ".ssh"), filepath.Join(home, ".gnupg"), filepath.Join(home, ".aws"),
		filepath.Join(home, ".config/macuahuitl"), filepath.Join(home, ".local/share/macuahuitl/sub")}
	for _, d := range bad {
		if _, err := ValidateDir(d); err == nil {
			t.Errorf("%s debió rechazarse", d)
		}
	}
	// $HOME exacto y las carpetas desde donde algo se ejecuta o se carga solo.
	for _, sub := range []string{".config/autostart", ".config/systemd/user", ".local/bin", ".local/share/applications", "bin", ".kube", ".cargo/bin", ".bashrc.d"} {
		os.MkdirAll(filepath.Join(home, sub), 0o700)
		if _, err := ValidateDir(filepath.Join(home, sub)); err == nil {
			t.Errorf("~/%s debió rechazarse", sub)
		}
	}
	if _, err := ValidateDir(home); err == nil {
		t.Error("$HOME exacto debió rechazarse")
	}
	if sub := filepath.Join(home, "Descargas", "imagenes"); true { // lo demás de $HOME sí es válido
		os.MkdirAll(sub, 0o700)
		if _, err := ValidateDir(sub); err != nil {
			t.Errorf("subcarpeta normal de $HOME: %v", err)
		}
	}
	// Una carpeta de datos extra de la app.
	data := t.TempDir()
	if _, err := ValidateDir(filepath.Join(data), data); err == nil {
		t.Error("DenyDirs ignorada")
	}
	// Ni relativa, ni inexistente, ni un archivo.
	f := filepath.Join(ok, "f")
	os.WriteFile(f, nil, 0o600)
	for _, d := range []string{"rel/dir", filepath.Join(ok, "no-existe"), f, ""} {
		if _, err := ValidateDir(d); err == nil {
			t.Errorf("%q debió rechazarse", d)
		}
	}
	// "..": se limpia antes de comparar (no sirve para escapar de la lista).
	if _, err := ValidateDir(ok + "/../../../etc"); err == nil {
		t.Error("ruta con .. hacia /etc aceptada")
	}
}

func TestValidateDirSymlinks(t *testing.T) {
	real := t.TempDir()
	link := filepath.Join(t.TempDir(), "enlace")
	os.Symlink(real, link)
	if _, err := ValidateDir(link); err == nil || !strings.Contains(err.Error(), "enlace simbólico") {
		t.Fatalf("la carpeta misma es un enlace: debió rechazarse por eso (%v)", err)
	}
	// Un enlace en un componente anterior se resuelve y se compara ya resuelto.
	if _, err := os.Stat("/usr/share"); err == nil {
		ancestor := filepath.Join(t.TempDir(), "u")
		os.Symlink("/usr", ancestor)
		if _, err := ValidateDir(filepath.Join(ancestor, "share")); err == nil {
			t.Fatal("un enlace a /usr sirvió para esquivar la lista de carpetas sensibles")
		}
	}
	// Con un ancestro enlazado a una carpeta normal se acepta y se devuelve la ruta real.
	anc := filepath.Join(t.TempDir(), "a")
	os.Symlink(real, anc)
	os.Mkdir(filepath.Join(real, "sub"), 0o700)
	got, err := ValidateDir(filepath.Join(anc, "sub"))
	if err != nil || got != filepath.Join(real, "sub") {
		t.Fatalf("ancestro enlazado: %q %v", got, err)
	}
}

// ---- publicar una carpeta ----

func TestSourceFolder(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.bin"), []byte("AAA"), 0o600)
	os.WriteFile(filepath.Join(dir, "b.cfg"), []byte("BB"), 0o600)
	os.Mkdir(filepath.Join(dir, "sub"), 0o700)
	os.WriteFile(filepath.Join(dir, "sub", "hondo.txt"), []byte("hondo"), 0o600)
	secret := filepath.Join(t.TempDir(), "secreto")
	os.WriteFile(secret, []byte("no"), 0o600)
	os.Symlink(secret, filepath.Join(dir, "enlace"))
	if err := sys.Mkfifo(filepath.Join(dir, "tuberia")); err != nil {
		t.Fatal(err)
	}
	s := testSource(t, &source{dir: dir})
	read := func(name string) (string, error) {
		f, _, err := s.open(name)
		if err != nil {
			return "", err
		}
		defer f.Close()
		b, _ := io.ReadAll(f)
		return string(b), nil
	}
	if got, err := read("a.bin"); err != nil || got != "AAA" {
		t.Fatalf("a.bin: %q %v", got, err)
	}
	if got, err := read("/b.cfg"); err != nil || got != "BB" {
		t.Fatalf("/b.cfg: %q %v", got, err)
	}
	for _, name := range []string{"enlace", "tuberia", "sub", "sub/hondo.txt", "../" + filepath.Base(dir) + "/a.bin", "..", ".", "", "no-existe", "a.bin/..", `sub\hondo.txt`, "a\x00.bin"} {
		if got, err := read(name); err == nil {
			t.Errorf("%q se sirvió: %q", name, got)
		}
		if s.exists(name) {
			t.Errorf("exists(%q) = true", name)
		}
	}
	var names []string
	for _, fi := range s.list() {
		names = append(names, fi.Name())
	}
	if strings.Join(names, ",") != "a.bin,b.cfg" {
		t.Fatalf("listado = %v (sin enlace, FIFO ni subcarpetas)", names)
	}
}

// Un enlace puesto entre el Lstat y el open no se sigue: lo abierto debe ser lo listado.
func TestSourceOpenSameFile(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a"), []byte("1"), 0o600)
	other := filepath.Join(t.TempDir(), "otro")
	os.WriteFile(other, []byte("2"), 0o600)
	s := testSource(t, &source{dir: dir})
	f, fi, err := s.open("a")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	li, _ := os.Lstat(filepath.Join(dir, "a"))
	if !os.SameFile(li, fi) {
		t.Fatal("open devolvió otro archivo que el listado")
	}
}

func TestSourceCombinesFilesAndFolder(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "carpeta.txt"), []byte("c"), 0o600)
	loose, _ := image(t, "suelto.bin", 5)
	s := testSource(t, &source{dir: dir, files: map[string]string{"suelto.bin": loose}})
	for _, n := range []string{"carpeta.txt", "suelto.bin"} {
		if !s.exists(n) {
			t.Errorf("%s no publicado", n)
		}
	}
	if len(s.list()) != 2 {
		t.Fatalf("list = %v", s.list())
	}
}

// Misma carpeta para leer y escribir: lo que aún se escribe no se sirve.
func TestSourceHidesFileBeingReceived(t *testing.T) {
	dir := t.TempDir()
	rcv, _ := newReceiver(dir, 0, 0)
	s := testSource(t, &source{dir: dir, rcv: rcv})
	f, _ := rcv.create("entrante", 0)
	f.Write([]byte("a medias"))
	if s.exists("entrante") {
		t.Fatal("se sirve un archivo que aún se escribe")
	}
	if _, _, err := s.open("entrante"); err == nil {
		t.Fatal("open sirvió un archivo en escritura")
	}
	if len(s.list()) != 0 {
		t.Fatalf("list = %v", s.list())
	}
	f.commit()
	if !s.exists("entrante") {
		t.Fatal("ya terminado debe servirse")
	}
	g, _ := rcv.create("descartado", 0)
	g.abort()
	if s.exists("descartado") {
		t.Fatal("abort dejó rastro")
	}
}

func TestServeFolderOverTFTPAndHTTP(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "r1.cfg"), []byte("hostname R1"), 0o600)
	os.Mkdir(filepath.Join(dir, "sub"), 0o700)
	os.WriteFile(filepath.Join(dir, "sub", "x"), []byte("x"), 0o600)
	os.Symlink("/etc/hostname", filepath.Join(dir, "enlace"))
	s, _ := startCfg(t, Config{Proto: "tftp", FromDir: dir})
	c := dialTFTP(t, s.addr)
	if got, _ := c.get("r1.cfg", 512); string(got) != "hostname R1" {
		t.Fatalf("tftp: %q", got)
	}
	for _, name := range []string{"sub/x", "../x", "enlace", "sub"} {
		c.send(c.srv, rrq(name))
		c.expectError(1)
	}
	var audited bool
	for _, x := range s.waitTransfers(t, 5) { // la lectura se registra en su goroutine, los rechazos en el bucle
		if x.Result == "ok" && x.Path == filepath.Join(dir, "r1.cfg") && x.Dir == "lectura" {
			audited = true
		}
	}
	if !audited {
		t.Fatalf("auditoría: %+v", s.transfers())
	}
	h, _ := startCfg(t, Config{Proto: "http", FromDir: dir})
	resp, err := http.Get("http://" + h.addr + "/r1.cfg")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !bytes.Equal(b, []byte("hostname R1")) {
		t.Fatalf("http: %q", b)
	}
	for _, p := range []string{"/sub/x", "/enlace", "/sub", "/../r1.cfg", "/%2e%2e/r1.cfg"} {
		resp, err := http.Get("http://" + h.addr + p)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode == 200 {
			t.Errorf("%s respondió 200", p)
		}
	}
}

func TestServeRejectsSensitiveFolders(t *testing.T) {
	for _, c := range []Config{
		{Addr: "127.0.0.1:0", Proto: "tftp", FromDir: "/etc"},
		{Addr: "127.0.0.1:0", Proto: "tftp", Write: true, RecvDir: "/usr"},
	} {
		if err := Serve(t.Context(), c); err == nil {
			t.Errorf("%+v debió fallar", c)
		}
	}
}

// swapForLink reemplaza dir por un enlace simbólico a other (la carpeta original se muda a dir+".orig").
func swapForLink(t *testing.T, dir, other string) string {
	t.Helper()
	if err := os.Rename(dir, dir+".orig"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(other, dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(dir); os.Rename(dir+".orig", dir) })
	return dir + ".orig"
}

// Cambiar la carpeta de recepción por un enlace simbólico después de validarla no desvía lo que se escribe.
func TestReceiverPinnedAgainstSymlinkSwap(t *testing.T) {
	recv, elsewhere := filepath.Join(t.TempDir(), "recv"), t.TempDir()
	os.Mkdir(recv, 0o700)
	src, rcv, err := prepare(Config{Addr: "127.0.0.1:6969", Proto: "tftp", Write: true, RecvDir: recv, Allow: []netip.Addr{netip.MustParseAddr("127.0.0.1")}})
	if err != nil {
		t.Fatal(err)
	}
	defer closeAll(src, rcv)
	orig := swapForLink(t, recv, elsewhere)
	f, err := rcv.create("config.txt", 0)
	if err != nil {
		t.Fatal(err)
	}
	f.Write([]byte("datos"))
	f.commit()
	if _, err := os.Stat(filepath.Join(elsewhere, "config.txt")); err == nil {
		t.Fatal("el archivo cayó en la carpeta a la que apunta el enlace nuevo")
	}
	if _, err := os.Stat(filepath.Join(orig, "config.txt")); err != nil {
		t.Fatalf("no cayó en la carpeta validada: %v", err)
	}
	// Un archivo descartado también se borra de la carpeta fija.
	g, _ := rcv.create("descartado", 0)
	g.abort()
	if _, err := os.Stat(filepath.Join(orig, "descartado")); err == nil {
		t.Fatal("abort no borró el parcial de la carpeta fija")
	}
}

// Lo mismo con la carpeta publicada: se sigue sirviendo la validada, no el enlace.
func TestSourcePinnedAgainstSymlinkSwap(t *testing.T) {
	pub, elsewhere := filepath.Join(t.TempDir(), "pub"), t.TempDir()
	os.Mkdir(pub, 0o700)
	os.WriteFile(filepath.Join(pub, "a.bin"), []byte("original"), 0o600)
	os.WriteFile(filepath.Join(elsewhere, "a.bin"), []byte("OTRO"), 0o600)
	os.WriteFile(filepath.Join(elsewhere, "b.bin"), []byte("OTRO"), 0o600)
	src, rcv, err := prepare(Config{Addr: "127.0.0.1:6969", Proto: "tftp", FromDir: pub})
	if err != nil {
		t.Fatal(err)
	}
	defer closeAll(src, rcv)
	swapForLink(t, pub, elsewhere)
	f, _, err := src.open("a.bin")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(f)
	f.Close()
	if string(b) != "original" {
		t.Fatalf("sirvió %q desde el enlace", b)
	}
	if src.exists("b.bin") {
		t.Fatal("b.bin existe solo en la carpeta del enlace")
	}
	if n := len(src.list()); n != 1 {
		t.Fatalf("list = %d archivos", n)
	}
}

// Un archivo con enlaces duros (Nlink > 1) puede ser el mismo inodo que uno sensible: no se publica.
func TestHardLinkedFilesNotPublished(t *testing.T) {
	dir, other := t.TempDir(), t.TempDir()
	secret := filepath.Join(other, "secreto")
	os.WriteFile(secret, []byte("no"), 0o600)
	if err := os.Link(secret, filepath.Join(dir, "enlace-duro")); err != nil {
		t.Skip("sin enlaces duros:", err)
	}
	os.WriteFile(filepath.Join(dir, "normal"), []byte("ok"), 0o600)
	src, rcv, err := prepare(Config{Addr: "127.0.0.1:6969", Proto: "tftp", FromDir: dir, Files: []string{secret}})
	if err == nil {
		closeAll(src, rcv)
		t.Fatal("un archivo suelto con enlace duro se publicó")
	}
	src, rcv, err = prepare(Config{Addr: "127.0.0.1:6969", Proto: "tftp", FromDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer closeAll(src, rcv)
	if src.exists("enlace-duro") {
		t.Error("exists(enlace-duro)")
	}
	if f, _, err := src.open("enlace-duro"); err == nil {
		f.Close()
		t.Error("open sirvió un enlace duro")
	}
	if !src.exists("normal") {
		t.Error("el archivo normal dejó de publicarse")
	}
	var names []string
	for _, fi := range src.list() {
		names = append(names, fi.Name())
	}
	if strings.Join(names, ",") != "normal" {
		t.Errorf("list = %v", names)
	}
}

// testSource abre la carpeta del source como lo hace prepare y la cierra al terminar la prueba.
func testSource(t *testing.T, s *source) *source {
	t.Helper()
	if s.dir != "" {
		root, err := os.OpenRoot(s.dir)
		if err != nil {
			t.Fatal(err)
		}
		s.root = root
		t.Cleanup(s.close)
	}
	return s
}

// Los archivos sueltos pasan por la misma lista de carpetas sensibles que FromDir y RecvDir.
func TestPublishRechazaArchivosSensibles(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	os.MkdirAll(filepath.Join(home, ".ssh"), 0o700)
	key := filepath.Join(home, ".ssh", "id_ed25519")
	os.WriteFile(key, []byte("k"), 0o600)
	cfgDir := t.TempDir()
	cfg := filepath.Join(cfgDir, "vault.mcv")
	os.WriteFile(cfg, []byte("v"), 0o600)
	link := filepath.Join(t.TempDir(), "inocente.txt") // un enlace a la llave no la disfraza
	os.Symlink(key, link)
	for name, c := range map[string]struct {
		f    string
		deny []string
	}{"ssh": {key, nil}, "enlace": {link, nil}, "config de la app": {cfg, []string{cfgDir}}, "etc": {"/etc/hostname", nil}} {
		if _, err := Publish([]string{c.f}, c.deny...); err == nil {
			t.Errorf("%s: publicado", name)
		}
		if _, _, err := prepare(Config{Addr: "127.0.0.1:0", Proto: "http", Files: []string{c.f}, DenyDirs: c.deny}); err == nil {
			t.Errorf("%s: prepare lo aceptó", name)
		}
	}
	for _, n := range []string{".bash_history", ".netrc"} {
		h := filepath.Join(home, n)
		os.WriteFile(h, []byte("h"), 0o600)
		if _, err := Publish([]string{h}); err == nil {
			t.Errorf("~/%s publicado", n)
		}
	}
	vis := filepath.Join(t.TempDir(), "visible.txt") // enlace visible a un oculto de $HOME
	os.Symlink(filepath.Join(home, ".netrc"), vis)
	if _, err := Publish([]string{vis}); err == nil {
		t.Error("enlace visible a ~/.netrc publicado")
	}
	fw := filepath.Join(home, "firmware.bin")
	os.WriteFile(fw, []byte("f"), 0o600)
	if _, err := Publish([]string{fw}); err != nil {
		t.Errorf("~/firmware.bin visible debe poder publicarse: %v", err)
	}
	ok := filepath.Join(t.TempDir(), "a.bin")
	os.WriteFile(ok, []byte("x"), 0o600)
	if _, err := Publish([]string{ok}); err != nil {
		t.Errorf("archivo normal: %v", err)
	}
}

// Todo lo oculto bajo $HOME (no solo la lista fija) se rechaza, como archivo suelto y como carpeta de envío/recepción.
func TestOcultosBajoHomeSeRechazan(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	for _, d := range []string{".password-store", ".thunderbird/x.default", ".cache/app", "Descargas/.oculta", "Descargas"} {
		os.MkdirAll(filepath.Join(home, d), 0o700)
	}
	for _, f := range []string{".password-store/x.gpg", ".thunderbird/x.default/logins.json", ".cache/app/a", "Descargas/.oculta/a", "Descargas/.env"} {
		os.WriteFile(filepath.Join(home, f), []byte("s"), 0o600)
		if _, err := Publish([]string{filepath.Join(home, f)}); err == nil {
			t.Errorf("~/%s publicado", f)
		}
	}
	for _, d := range []string{".password-store", ".thunderbird/x.default", ".cache/app", "Descargas/.oculta"} {
		if _, err := ValidateDir(filepath.Join(home, d)); err == nil {
			t.Errorf("~/%s aceptada como carpeta", d)
		}
	}
	os.WriteFile(filepath.Join(home, "c9300.bin"), []byte("f"), 0o600)
	os.WriteFile(filepath.Join(home, "Descargas", "r.cfg"), []byte("f"), 0o600)
	for _, f := range []string{"c9300.bin", "Descargas/r.cfg"} {
		if _, err := Publish([]string{filepath.Join(home, f)}); err != nil {
			t.Errorf("~/%s: %v", f, err)
		}
	}
	if _, err := ValidateDir(filepath.Join(home, "Descargas")); err != nil {
		t.Errorf("~/Descargas: %v", err)
	}
}
