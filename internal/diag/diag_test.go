package diag

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func fakeBin() string {
	_, f, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(f), "testdata", "bin")
}

func runner(t *testing.T, missing ...string) Runner {
	t.Helper()
	return Runner{LookPath: func(name string) (string, error) {
		for _, m := range missing {
			if m == name {
				return "", errors.New("not found")
			}
		}
		p := filepath.Join(fakeBin(), name)
		if _, err := os.Stat(p); err != nil {
			return "", err
		}
		return p, nil
	}}
}

func req(tool Tool, target string, opts map[string]string, dir string) Request {
	r := Request{Tool: tool, Options: opts, OutputDir: dir}
	if target != "" {
		r.Targets = []string{target}
	}
	return r
}

func TestBuildArgv(t *testing.T) {
	localTest(t)
	cases := []struct {
		r    Request
		want string
	}{
		{req(Ping, "192.0.2.1", map[string]string{"count": "4", "interval": "0.5", "size": "1200"}, ""), "-n -c 4 -i 0.5 -s 1200 192.0.2.1"},
		{req(Ping, "sw1.example", nil, ""), "-n -c 4 sw1.example"},
		{req(Traceroute, "192.0.2.1", map[string]string{"max_hops": "12"}, ""), "-n -m 12 192.0.2.1"},
		{req(Nmap, "192.0.2.0/24", map[string]string{"ports": "22,80,443-445", "scan": "connect", "timing": "3", "service_detection": "true"}, ""), "-sT -p 22,80,443-445 -T3 -sV -n -oG - 192.0.2.0/24"},
		{req(Nmap, "192.0.2.1", map[string]string{"scan": "syn"}, ""), "-sS -n -oG - 192.0.2.1"},
		{req(Nmap, "192.0.2.1", map[string]string{"scan": "ping"}, ""), "-sn -n -oG - 192.0.2.1"},
		{req(Iperf3, "192.0.2.1", map[string]string{"mode": "client", "port": "5201", "seconds": "10", "parallel": "4", "reverse": "true"}, ""), "-c 192.0.2.1 -p 5201 -t 10 -P 4 -R"},
		{req(Iperf3, "", map[string]string{"mode": "server", "port": "5201", "bind": "192.0.2.9"}, ""), "-s -B 192.0.2.9 -p 5201 -1"},
		{req(Pcap, "", map[string]string{"interface": "eth0", "seconds": "30", "packets": "1000", "filter": "tcp port 22 and host 192.0.2.1"}, "/out"), "-i eth0 -a duration:30 -c 1000 -f tcp port 22 and host 192.0.2.1"},
	}
	for _, c := range cases {
		bin, argv, err := Build(c.r)
		if err != nil {
			t.Errorf("Build(%v %v): %v", c.r.Tool, c.r.Options, err)
			continue
		}
		got := strings.Join(argv, " ")
		if !strings.HasPrefix(got, c.want) || bin == "" {
			t.Errorf("Build(%v %v) = %q %q, want prefix %q", c.r.Tool, c.r.Options, bin, got, c.want)
		}
	}
}

func TestBuildRejects(t *testing.T) {
	cases := map[string]Request{
		"target con guion":       req(Ping, "-iL", nil, ""),
		"target con espacio":     req(Ping, "a b", nil, ""),
		"cidr en ping":           req(Ping, "192.0.2.0/24", nil, ""),
		"cidr inválido":          req(Nmap, "192.0.2.0/33", nil, ""),
		"sin target":             req(Ping, "", nil, ""),
		"varios targets en ping": {Tool: Ping, Targets: []string{"a", "b"}},
		"opción desconocida":     req(Ping, "192.0.2.1", map[string]string{"script": "x"}, ""),
		"count fuera de rango":   req(Ping, "192.0.2.1", map[string]string{"count": "1000"}, ""),
		"interval muy bajo":      req(Ping, "192.0.2.1", map[string]string{"interval": "0.01"}, ""),
		"puertos nmap raros":     req(Nmap, "192.0.2.1", map[string]string{"ports": "22;rm"}, ""),
		"scan desconocido":       req(Nmap, "192.0.2.1", map[string]string{"scan": "idle"}, ""),
		"iperf modo":             req(Iperf3, "192.0.2.1", map[string]string{"mode": "proxy"}, ""),
		"iperf cliente sin host": req(Iperf3, "", map[string]string{"mode": "client"}, ""),
		"pcap sin interfaz":      req(Pcap, "", map[string]string{"seconds": "10"}, "/out"),
		"pcap interfaz rara":     req(Pcap, "", map[string]string{"interface": "eth0 -w /etc/x"}, "/out"),
		"pcap sin carpeta":       req(Pcap, "", map[string]string{"interface": "eth0"}, ""),
		"pcap duración":          req(Pcap, "", map[string]string{"interface": "eth0", "seconds": "99999"}, "/out"),
		"herramienta":            req(Tool("sh"), "x", nil, ""),
	}
	for name, r := range cases {
		if _, _, err := Build(r); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestRunStreamsAndSaves(t *testing.T) {
	dir := t.TempDir()
	var lines []string
	res, err := runner(t).Run(context.Background(), req(Ping, "192.0.2.1", map[string]string{"count": "2"}, dir), func(l string) { lines = append(lines, l) })
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 0 || len(lines) != 3 || !strings.HasPrefix(lines[0], "ARGV: -n -c 2 192.0.2.1") {
		t.Fatalf("res=%+v lines=%v", res, lines)
	}
	b, err := os.ReadFile(res.OutputPath)
	if err != nil || !strings.Contains(string(b), "línea 2 de ping") || !strings.HasPrefix(filepath.Base(res.OutputPath), "diag_ping_") {
		t.Fatalf("output %q: %v", res.OutputPath, err)
	}
	fi, _ := os.Stat(res.OutputPath)
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("perm %o", fi.Mode().Perm())
	}
	if strings.Join(res.Argv, " ") != "-n -c 2 192.0.2.1" {
		t.Fatalf("argv = %v", res.Argv)
	}
}

func TestRunExitCode(t *testing.T) {
	r := runner(t)
	r.extraEnv = []string{"FAKE_EXIT=2"}
	res, err := r.Run(context.Background(), req(Ping, "192.0.2.1", nil, t.TempDir()), func(string) {})
	if err != nil || res.ExitCode != 2 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

func TestNotInstalled(t *testing.T) {
	_, err := runner(t, "nmap").Run(context.Background(), req(Nmap, "192.0.2.1", nil, t.TempDir()), func(string) {})
	if !errors.Is(err, ErrNotInstalled) || !strings.Contains(err.Error(), "apt install nmap") {
		t.Fatalf("err = %v", err)
	}
}

func TestTracerouteFallsBackToTracepath(t *testing.T) {
	var lines []string
	_, err := runner(t, "traceroute").Run(context.Background(), req(Traceroute, "192.0.2.1", nil, t.TempDir()), func(l string) { lines = append(lines, l) })
	if err != nil || len(lines) < 2 || !strings.Contains(lines[1], "tracepath") {
		t.Fatalf("err=%v lines=%v", err, lines)
	}
}

func TestCancelKillsProcess(t *testing.T) {
	r := runner(t)
	r.LookPath = func(string) (string, error) { return filepath.Join(fakeBin(), "sleeper"), nil }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan Result, 1)
	go func() {
		res, _ := r.Run(ctx, req(Ping, "192.0.2.1", nil, t.TempDir()), func(string) {})
		done <- res
	}()
	time.Sleep(200 * time.Millisecond)
	start := time.Now()
	cancel()
	select {
	case res := <-done:
		if res.ExitCode == 0 || time.Since(start) > 5*time.Second {
			t.Fatalf("exit=%d after %v", res.ExitCode, time.Since(start))
		}
	case <-time.After(6 * time.Second):
		t.Fatal("process not killed on cancel")
	}
}

func TestPcapWritesBinaryNotStream(t *testing.T) {
	dir := t.TempDir()
	var lines []string
	res, err := runner(t).Run(context.Background(), req(Pcap, "", map[string]string{"interface": "eth0", "seconds": "5", "filter": "tcp port 22; echo pwned"}, dir), func(l string) { lines = append(lines, l) })
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(res.OutputPath, ".pcapng") {
		t.Fatalf("path %q", res.OutputPath)
	}
	b, _ := os.ReadFile(res.OutputPath)
	if len(b) == 0 || b[0] != 0x0a {
		t.Fatalf("pcap not written: %v", b)
	}
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "-f tcp port 22; echo pwned -w") || strings.Contains(joined, "\x0a\x0d") {
		t.Fatalf("stream = %q", joined)
	}
	if !strings.Contains(joined, "Packets captured") {
		t.Fatal("stderr progress not streamed")
	}
}
