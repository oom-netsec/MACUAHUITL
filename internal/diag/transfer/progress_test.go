package transfer

import (
	"bytes"
	"context"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/diag/fileserve"
)

func TestProgressNoPasaDeDiezPorSegundo(t *testing.T) {
	clock := time.Unix(1000, 0)
	var got []Progress
	p := newTracker(func(x Progress) { got = append(got, x) }, func() time.Time { return clock })
	p.setTotal(1_000_000)
	for i := 0; i < 2000; i++ { // 2000 escrituras de 500 bytes, una cada milisegundo: 2 s
		clock = clock.Add(time.Millisecond)
		p.add(500)
	}
	p.finish()
	if n := len(got); n > 21+1 || n < 15 { // ≤ 10/s durante 2 s, más el aviso final
		t.Fatalf("%d eventos en 2 s", n)
	}
	last := got[len(got)-1]
	if last.Bytes != 1_000_000 || last.Total != 1_000_000 {
		t.Fatalf("el último evento debe traer todo: %+v", last)
	}
	for i := 1; i < len(got); i++ {
		if got[i].Bytes < got[i-1].Bytes {
			t.Fatalf("los bytes no bajan: %+v", got)
		}
	}
	// 500 bytes por ms = 500 000 B/s
	mid := got[len(got)/2]
	if math.Abs(mid.BytesPerSec-500_000) > 25_000 {
		t.Fatalf("velocidad = %v", mid.BytesPerSec)
	}
}

func TestProgressSinTotalYSinFinishNoRevienta(t *testing.T) {
	var p *progressTracker
	p.add(5)
	p.setTotal(9)
	p.finish() // un rastreador nulo (sin OnProgress) no hace nada
	clock := time.Unix(0, 0)
	var got []Progress
	q := newTracker(func(x Progress) { got = append(got, x) }, func() time.Time { return clock })
	q.add(10) // el primer aviso sale de inmediato
	q.finish()
	q.finish() // finish dos veces no repite
	if len(got) != 2 || got[0].Total != 0 || got[1].Bytes != 10 {
		t.Fatalf("got = %+v", got)
	}
}

func TestDownloadHTTPInformaProgreso(t *testing.T) {
	data := bytes.Repeat([]byte("0123456789abcdef"), 1<<14) // 256 KiB
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprint(len(data)))
		for off := 0; off < len(data); off += 8192 {
			w.Write(data[off : off+8192])
			time.Sleep(time.Millisecond)
		}
	}))
	defer srv.Close()
	var got []Progress
	res, err := Download(context.Background(), Request{Net: rawNet, URL: &url.URL{Scheme: "http", Host: strings.TrimPrefix(srv.URL, "http://"), Path: "/f.bin"}, DestDir: t.TempDir(),
		OnProgress: func(p Progress) { got = append(got, p) }})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) < 2 || len(got) > 40 {
		t.Fatalf("%d eventos", len(got))
	}
	last := got[len(got)-1]
	if last.Bytes != int64(len(data)) || last.Total != int64(len(data)) || res.Bytes != last.Bytes {
		t.Fatalf("último = %+v res = %+v", last, res)
	}
}

func TestProgresoEnTodosLosProtocolos(t *testing.T) {
	data := bytes.Repeat([]byte("interface Gi0/1\n"), 2000) // 32 KB
	for _, proto := range []string{"tftp", "ftp", "scp", "sftp"} {
		t.Run(proto, func(t *testing.T) {
			pub, recv, dest := t.TempDir(), t.TempDir(), t.TempDir()
			os.WriteFile(filepath.Join(pub, "a.bin"), data, 0o600)
			ready := startSrv(t, fileserve.Config{Proto: proto, FromDir: pub, Write: true, RecvDir: recv})
			var down, up []Progress
			dr := reqFor(t, proto, ready, "a.bin")
			dr.DestDir, dr.OnProgress = dest, func(p Progress) { down = append(down, p) }
			if _, err := Download(context.Background(), dr); err != nil {
				t.Fatal(err)
			}
			ur := reqFor(t, proto, ready, "b.bin")
			ur.FromDir, ur.Name, ur.OnProgress = pub, "a.bin", func(p Progress) { up = append(up, p) }
			if _, err := Upload(context.Background(), ur); err != nil {
				t.Fatal(err)
			}
			for what, ev := range map[string][]Progress{"bajada": down, "subida": up} {
				if len(ev) == 0 || ev[len(ev)-1].Bytes != int64(len(data)) {
					t.Fatalf("%s: %+v", what, ev)
				}
				if ev[len(ev)-1].Total != int64(len(data)) && !(what == "bajada" && proto == "tftp") { // TFTP baja sin tsize del servidor de pruebas
					t.Errorf("%s: total desconocido en %s: %+v", what, proto, ev[len(ev)-1])
				}
			}
		})
	}
}
