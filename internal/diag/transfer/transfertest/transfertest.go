// Package transfertest da servidores falsos de listado para probar el explorador de transferencias
// desde paquetes que no pueden abrir sockets (cmd/mctl, servicios). Solo para pruebas.
package transfertest

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// HTTPIndex sirve html como índice de cualquier carpeta y devuelve la URL base («http://127.0.0.1:puerto»).
func HTTPIndex(t testing.TB, html string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		io.WriteString(w, html)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}
