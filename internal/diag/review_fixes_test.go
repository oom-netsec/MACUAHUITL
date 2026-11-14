package diag

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func withBin(t *testing.T, name string) Runner {
	r := runner(t)
	r.LookPath = func(string) (string, error) { return filepath.Join(fakeBin(), name), nil }
	return r
}

func TestHugeLineDoesNotHang(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var lines []string
	res, err := withBin(t, "bigline").Run(ctx, req(Ping, "192.0.2.1", nil, t.TempDir()), func(l string) { lines = append(lines, l) })
	if err != nil || res.ExitCode != 0 || len(lines) != 2 || len(lines[0]) != 2*1024*1024 || lines[1] != "fin" {
		t.Fatalf("err=%v res=%+v lines=%d", err, res, len(lines))
	}
}

func TestCancelKillsStubbornChildren(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "pid")
	r := withBin(t, "stubborn")
	r.extraEnv = []string{"PIDFILE=" + pidFile}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.Run(ctx, req(Ping, "192.0.2.1", nil, t.TempDir()), func(string) {}); close(done) }()
	deadline := time.Now().Add(3 * time.Second)
	for {
		if b, _ := os.ReadFile(pidFile); len(b) > 0 || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return")
	}
	b, _ := os.ReadFile(pidFile)
	pid, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	time.Sleep(200 * time.Millisecond)
	if pid > 0 && syscall.Kill(pid, 0) == nil {
		syscall.Kill(pid, syscall.SIGKILL)
		t.Fatalf("child %d survived the cancel (orphan)", pid)
	}
}

func TestSameSecondRunsDoNotCollide(t *testing.T) {
	dir := t.TempDir()
	r := runner(t)
	var paths []string
	for i := 0; i < 2; i++ {
		res, err := r.Run(context.Background(), req(Ping, "192.0.2.1", nil, dir), func(string) {})
		if err != nil {
			t.Fatal(err)
		}
		paths = append(paths, res.OutputPath)
	}
	if paths[0] == paths[1] {
		t.Fatalf("same path twice: %s", paths[0])
	}
	for i := 0; i < 2; i++ {
		res, err := r.Run(context.Background(), req(Pcap, "", map[string]string{"interface": "eth0", "seconds": "1"}, dir), func(string) {})
		if err != nil {
			t.Fatal(err)
		}
		fi, _ := os.Stat(res.OutputPath)
		if fi.Mode().Perm() != 0o600 || fi.Size() == 0 {
			t.Fatalf("pcap %s: %v", res.OutputPath, fi)
		}
		paths = append(paths, res.OutputPath)
	}
	if paths[2] == paths[3] {
		t.Fatal("pcap overwritten in the same second")
	}
}

func TestResultReportsRealBinary(t *testing.T) {
	res, err := runner(t, "traceroute").Run(context.Background(), req(Traceroute, "192.0.2.1", map[string]string{"max_hops": "5"}, t.TempDir()), func(string) {})
	if err != nil || res.Bin != "tracepath" || strings.Join(res.Argv, " ") != "-n -m 5 192.0.2.1" {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	res, _ = runner(t).Run(context.Background(), req(Pcap, "", map[string]string{"interface": "eth0"}, t.TempDir()), func(string) {})
	if res.Bin != "dumpcap" || !strings.Contains(strings.Join(res.Argv, " "), "-w "+res.OutputPath) {
		t.Fatalf("pcap argv must include the real -w path: %+v", res)
	}
}

func TestStrictNumbersAndInterface(t *testing.T) {
	localTest(t)
	for name, r := range map[string]Request{
		"NaN":         req(Ping, "192.0.2.1", map[string]string{"count": "NaN"}, ""),
		"exponente":   req(Ping, "192.0.2.1", map[string]string{"count": "1e1"}, ""),
		"float count": req(Ping, "192.0.2.1", map[string]string{"count": "4.0"}, ""),
		"signo":       req(Ping, "192.0.2.1", map[string]string{"size": "-0"}, ""),
		"mas":         req(Ping, "192.0.2.1", map[string]string{"count": "+5"}, ""),
		"iface guion": req(Pcap, "", map[string]string{"interface": "-w"}, "/out"),
		"iface solo":  req(Pcap, "", map[string]string{"interface": "-"}, "/out"),
		"timing neg":  req(Nmap, "192.0.2.1", map[string]string{"timing": "-0"}, ""),
	} {
		if _, _, err := Build(r); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, argv, err := Build(req(Ping, "192.0.2.1", map[string]string{"interval": "0.5"}, "")); err != nil || !strings.Contains(strings.Join(argv, " "), "-i 0.5") {
		t.Fatalf("interval 0.5: %v %v", argv, err)
	}
	if _, argv, err := Build(req(Nmap, "2001:db8::1", nil, "")); err != nil || !strings.Contains(strings.Join(argv, " "), "-6") {
		t.Fatalf("ipv6 nmap without -6: %v %v", argv, err)
	}
	if _, argv, err := Build(req(Iperf3, "", map[string]string{"mode": "server", "seconds": "10", "bind": "192.0.2.9"}, "")); err != nil || strings.Contains(strings.Join(argv, " "), "-t") {
		t.Fatalf("server must ignore seconds: %v %v", argv, err)
	}
}

// El servidor de iperf3 no escucha en todas las interfaces: exige -B con una IP de esta máquina,
// puerto no privilegiado y un tope de tiempo.
func TestIperfServerRestringido(t *testing.T) {
	localIPs = func() []netip.Addr { return []netip.Addr{netip.MustParseAddr("192.0.2.9"), netip.MustParseAddr("::1")} }
	t.Cleanup(func() { localIPs = realLocalIPs })
	srv := func(o map[string]string) error {
		o["mode"] = "server"
		_, _, err := Build(req(Iperf3, "", o, ""))
		return err
	}
	for name, o := range map[string]map[string]string{
		"sin bind": {}, "bind ajeno": {"bind": "198.51.100.1"}, "bind 0.0.0.0": {"bind": "0.0.0.0"}, "bind nombre": {"bind": "localhost"},
		"bind bandera": {"bind": "-1"}, "puerto 80": {"bind": "192.0.2.9", "port": "80"}, "puerto 1023": {"bind": "192.0.2.9", "port": "1023"},
	} {
		if srv(o) == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if err := srv(map[string]string{"bind": "192.0.2.9", "port": "1024"}); err != nil {
		t.Errorf("ok rechazado: %v", err)
	}
	if err := srv(map[string]string{"bind": "::1"}); err != nil {
		t.Errorf("ipv6 local rechazado: %v", err)
	}
	// El cliente no usa bind.
	if _, _, err := Build(req(Iperf3, "192.0.2.1", map[string]string{"bind": "192.0.2.9"}, "")); err == nil {
		t.Error("bind en cliente aceptado")
	}
}

func TestIperfServerTieneTope(t *testing.T) {
	localIPs = func() []netip.Addr { return []netip.Addr{netip.MustParseAddr("192.0.2.9")} }
	iperfServerMax = 300 * time.Millisecond
	t.Cleanup(func() { localIPs = realLocalIPs; iperfServerMax = 10 * time.Minute })
	start := time.Now()
	_, err := withBin(t, "sleeper").Run(context.Background(), req(Iperf3, "", map[string]string{"mode": "server", "bind": "192.0.2.9"}, ""), func(string) {})
	_ = err
	if d := time.Since(start); d > 8*time.Second {
		t.Fatalf("el servidor no se cortó por tope: %v", d)
	}
}

func localTest(t *testing.T) {
	localIPs = func() []netip.Addr { return []netip.Addr{netip.MustParseAddr("192.0.2.9")} }
	t.Cleanup(func() { localIPs = realLocalIPs })
}

func TestLocalIPsRealIncluyeLoopback(t *testing.T) {
	if !isLocalIP(netip.MustParseAddr("127.0.0.1")) || isLocalIP(netip.MustParseAddr("0.0.0.0")) {
		t.Fatal("127.0.0.1 debe ser local y 0.0.0.0 no")
	}
}
