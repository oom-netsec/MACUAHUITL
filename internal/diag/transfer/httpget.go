package transfer

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"
)

// httpClient arma el cliente HTTP(S). El certificado se verifica salvo Insecure. Cada conexión,
// también las de una redirección, pasa por Net.Dial: un destino sin autorizar se niega.
func (r *Request) httpClient() (cl *http.Client, closeIdle func()) {
	tr := &http.Transport{
		Proxy: nil, // nunca por el proxy del entorno: la salida es solo la autorizada
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			h, p, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			port, err := strconv.ParseUint(p, 10, 16)
			if err != nil {
				return nil, err
			}
			return r.Net.Dial(ctx, "tcp", h, uint16(port))
		},
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: r.Insecure, MinVersion: tls.VersionTLS12}, //nolint:gosec // --insecure explícito y auditado
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		DisableKeepAlives:     true,
	}
	cl = &http.Client{Transport: tr, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return errors.New("demasiadas redirecciones")
		}
		if via[0].URL.Scheme == "https" && req.URL.Scheme != "https" { // no se baja de nivel: el contenido iría en claro
			return errors.New("redirección de https a http rechazada")
		}
		return nil
	}}
	return cl, tr.CloseIdleConnections
}

// httpGet baja por HTTP(S).
func (r *Request) httpGet(ctx context.Context, w io.Writer) error {
	cl, closeIdle := r.httpClient()
	defer closeIdle()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.URL.String(), nil)
	if err != nil {
		return err
	}
	req.URL.User = nil // la credencial no viaja en la URL
	resp, err := cl.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %s", resp.Status)
	}
	if max, _ := r.limits(); resp.ContentLength > max {
		return errTooBig
	}
	r.track.setTotal(resp.ContentLength)
	_, err = io.Copy(w, resp.Body)
	return err
}
