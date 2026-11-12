package gnmic

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openconfig/gnmi/proto/gnmi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type fakeGNMI struct {
	gnmi.UnimplementedGNMIServer
	gotSub chan *gnmi.SubscribeRequest
}

func auth(ctx context.Context) error {
	md, _ := metadata.FromIncomingContext(ctx)
	if len(md["username"]) != 1 || md["username"][0] != "noc" || md["password"][0] != "s3creta" {
		return status.Error(codes.Unauthenticated, "credenciales")
	}
	return nil
}

func (f *fakeGNMI) Get(ctx context.Context, r *gnmi.GetRequest) (*gnmi.GetResponse, error) {
	if err := auth(ctx); err != nil {
		return nil, err
	}
	if r.Encoding != gnmi.Encoding_JSON_IETF {
		return nil, status.Error(codes.InvalidArgument, "codificación")
	}
	return &gnmi.GetResponse{Notification: []*gnmi.Notification{{
		Timestamp: time.Unix(1700000000, 0).UnixNano(),
		Update:    []*gnmi.Update{{Path: r.Path[0], Val: &gnmi.TypedValue{Value: &gnmi.TypedValue_JsonIetfVal{JsonIetfVal: []byte(`{"in-octets":"1234","out-octets":"99"}`)}}}},
	}}}, nil
}

func (f *fakeGNMI) Subscribe(st gnmi.GNMI_SubscribeServer) error {
	if err := auth(st.Context()); err != nil {
		return err
	}
	req, err := st.Recv()
	if err != nil {
		return err
	}
	f.gotSub <- req
	prefix := &gnmi.Path{Elem: []*gnmi.PathElem{{Name: "system"}}}
	for i := 0; i < 2; i++ {
		st.Send(&gnmi.SubscribeResponse{Response: &gnmi.SubscribeResponse_Update{Update: &gnmi.Notification{Timestamp: time.Now().UnixNano(), Prefix: prefix,
			Update: []*gnmi.Update{{Path: &gnmi.Path{Elem: []*gnmi.PathElem{{Name: "cpus"}, {Name: "cpu", Key: map[string]string{"index": "0"}}, {Name: "state"}, {Name: "total"}}},
				Val: &gnmi.TypedValue{Value: &gnmi.TypedValue_UintVal{UintVal: uint64(10 + i)}}}}}}})
	}
	st.Send(&gnmi.SubscribeResponse{Response: &gnmi.SubscribeResponse_SyncResponse{SyncResponse: true}})
	<-st.Context().Done()
	return nil
}

// tlsServer arranca un gNMI en loopback con un certificado propio; devuelve el puerto y la CA en PEM.
func tlsServer(t *testing.T, f *fakeGNMI) (uint16, []byte) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "gnmi-lab"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := grpc.NewServer(grpc.Creds(credentials.NewServerTLSFromCert(&cert)))
	gnmi.RegisterGNMIServer(s, f)
	go s.Serve(l)
	t.Cleanup(s.Stop)
	return uint16(l.Addr().(*net.TCPAddr).Port), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func dialer(n *atomic.Int32) Dialer {
	return func(ctx context.Context, network, host string, port uint16) (net.Conn, error) {
		n.Add(1)
		var d net.Dialer
		return d.DialContext(ctx, network, net.JoinHostPort(host, itoa(port)))
	}
}

func itoa(p uint16) string { return strconv.Itoa(int(p)) }

func TestGet(t *testing.T) {
	port, ca := tlsServer(t, &fakeGNMI{})
	var dials atomic.Int32
	tg := Target{Host: "127.0.0.1", Port: port, Username: "noc", Password: "s3creta", CA: ca, Timeout: 3 * time.Second}
	ups, err := Get(context.Background(), dialer(&dials), tg, []string{"/interfaces/interface[name=GigabitEthernet1/0/1]/state/counters"}, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(ups) != 1 || ups[0].Path != "/interfaces/interface[name=GigabitEthernet1/0/1]/state/counters" || ups[0].Value.(map[string]any)["in-octets"] != "1234" {
		t.Fatalf("updates = %+v", ups)
	}
	if dials.Load() == 0 {
		t.Fatal("la conexión no pasó por el dialer")
	}
	tg.Password = "otra"
	if _, err := Get(context.Background(), dialer(&dials), tg, []string{"/system"}, ""); err == nil || !strings.Contains(err.Error(), "Unauthenticated") {
		t.Fatalf("credencial equivocada: %v", err)
	}
}

func TestTLSVerificaPorDefecto(t *testing.T) {
	port, _ := tlsServer(t, &fakeGNMI{})
	var dials atomic.Int32
	tg := Target{Host: "127.0.0.1", Port: port, Username: "noc", Password: "s3creta", Timeout: 2 * time.Second}
	if _, err := Get(context.Background(), dialer(&dials), tg, []string{"/system"}, ""); err == nil {
		t.Fatal("certificado autofirmado aceptado sin CA propia")
	}
	if _, err := Get(context.Background(), dialer(&dials), Target{Host: "127.0.0.1", Port: port, Username: "noc", Password: "s3creta", CA: []byte("basura")}, []string{"/system"}, ""); err == nil {
		t.Fatal("CA inválida aceptada")
	}
}

func TestSubscribeSample(t *testing.T) {
	f := &fakeGNMI{gotSub: make(chan *gnmi.SubscribeRequest, 1)}
	port, ca := tlsServer(t, f)
	var dials atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var got []Update
	synced := false
	err := Subscribe(ctx, dialer(&dials), Target{Host: "127.0.0.1", Port: port, Username: "noc", Password: "s3creta", CA: ca},
		[]string{"/system/cpus/cpu/state/total"}, "sample", 10*time.Second, func(u Update) {
			if u.Sync {
				synced = true
				cancel()
				return
			}
			got = append(got, u)
		})
	if err != nil {
		t.Fatal(err)
	}
	req := <-f.gotSub
	sl := req.GetSubscribe()
	if sl.Mode != gnmi.SubscriptionList_STREAM || sl.Subscription[0].Mode != gnmi.SubscriptionMode_SAMPLE || sl.Subscription[0].SampleInterval != uint64(10*time.Second) {
		t.Fatalf("suscripción = %v", sl)
	}
	if !synced || len(got) != 2 || got[1].Path != "/system/cpus/cpu[index=0]/state/total" || got[1].Value != uint64(11) {
		t.Fatalf("updates = %+v", got)
	}
	if err := Subscribe(context.Background(), dialer(&dials), Target{Host: "127.0.0.1", Port: port}, []string{"/x"}, "poll", 0, nil); err == nil {
		t.Fatal("modo desconocido aceptado")
	}
}

func TestParsePath(t *testing.T) {
	p, err := ParsePath("/interfaces/interface[name=Ethernet1/1]/state/counters")
	if err != nil || len(p.Elem) != 4 || p.Elem[1].Key["name"] != "Ethernet1/1" {
		t.Fatalf("%v %v", p, err)
	}
	if PathString(nil, p) != "/interfaces/interface[name=Ethernet1/1]/state/counters" {
		t.Fatal(PathString(nil, p))
	}
	for _, bad := range []string{"", "/a[b", "/a[=x]", "/a]b"} {
		if _, err := ParsePath(bad); err == nil {
			t.Errorf("%q aceptada", bad)
		}
	}
}
