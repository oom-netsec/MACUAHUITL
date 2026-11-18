package diag

import (
	"os"
	"strings"
	"testing"
)

// En Windows real: la función de verdad nunca devuelve el DNS fantasma fec0:0:0:ffff:: ni una lista vacía con una NIC activa.
func TestSystemDNSHostsReal(t *testing.T) {
	hosts := SystemDNSHosts()
	for _, h := range hosts {
		if strings.HasPrefix(strings.ToLower(h), "fec0:") {
			t.Fatalf("resolver fantasma en la lista: %v", hosts)
		}
	}
	if len(hosts) == 0 {
		if os.Getenv("CI") != "" { // el runner del CI siempre tiene DNS: vacío ahí es un flag o una API mal usada
			t.Fatal("sin resolvers en el runner del CI")
		}
		t.Skip("sin adaptador activo con DNS en este equipo")
	}
}
