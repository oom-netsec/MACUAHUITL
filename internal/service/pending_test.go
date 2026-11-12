package service

import (
	"sync"
	"testing"
	"time"
)

func TestPendingTomaUnaVez(t *testing.T) {
	var p Pending[string]
	now := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	tok, exp := p.Add(now, 10*time.Minute, "uno")
	if tok == "" || len(tok) < 32 || !exp.Equal(now.Add(10*time.Minute)) {
		t.Fatalf("tok = %q exp = %v", tok, exp)
	}
	if v, e, ok := p.Take(tok); !ok || v != "uno" || !e.Equal(exp) {
		t.Fatalf("take = %q %v %v", v, e, ok)
	}
	if _, _, ok := p.Take(tok); ok {
		t.Fatal("el token ya se usó")
	}
	if _, _, ok := p.Take("no-existe"); ok {
		t.Fatal("token desconocido")
	}
	// devolver el token (una decisión mala) lo deja usable otra vez
	p.Restore(tok, "uno", exp)
	if v, _, ok := p.Take(tok); !ok || v != "uno" {
		t.Fatal("restore")
	}
}

func TestPendingEnParaleloSoloUnoGana(t *testing.T) {
	var p Pending[int]
	tok, _ := p.Add(time.Now(), time.Minute, 7)
	var wg sync.WaitGroup
	var mu sync.Mutex
	gana := 0
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, _, ok := p.Take(tok); ok {
				mu.Lock()
				gana++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if gana != 1 {
		t.Fatalf("ganaron %d", gana)
	}
}

func TestPendingVenceYTienTope(t *testing.T) {
	var p Pending[int]
	now := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	viejo, _ := p.Add(now, time.Minute, 0)
	// al agregar más tarde se limpian los vencidos (aún lejos del tope)
	p.Add(now.Add(2*time.Minute), time.Hour, -1)
	if _, _, ok := p.Take(viejo); ok {
		t.Fatal("el vencido debió limpiarse")
	}
	var toks []string
	for i := 1; i <= PendingMax; i++ {
		tok, _ := p.Add(now.Add(2*time.Minute), time.Duration(i)*time.Hour, i)
		toks = append(toks, tok)
	}
	// el tope: el 17.º desplaza al más viejo (el de menor vencimiento)
	extra, _ := p.Add(now.Add(2*time.Minute), 99*time.Hour, 99)
	if _, _, ok := p.Take(toks[0]); ok {
		t.Fatal("el más viejo debió ceder su lugar")
	}
	if _, _, ok := p.Take(extra); !ok {
		t.Fatal("el nuevo debe estar")
	}
	if _, _, ok := p.Take(toks[1]); !ok {
		t.Fatal("el segundo debe seguir")
	}
}

// Devolver un token tampoco pasa del tope: el más viejo cede su lugar.
func TestPendingRestoreRespetaElTope(t *testing.T) {
	var p Pending[int]
	now := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	var toks []string
	for i := 1; i <= PendingMax; i++ {
		tok, _ := p.Add(now, time.Duration(i)*time.Hour, i)
		toks = append(toks, tok)
	}
	v, exp, ok := p.Take(toks[8]) // se toma uno del medio...
	if !ok {
		t.Fatal("take")
	}
	p.Add(now, 99*time.Hour, 99) // ...entra otro y el tope vuelve a llenarse...
	p.Restore(toks[8], v, exp)   // ...y al devolver el tomado se va el más viejo, no se pasa de 16
	if n := len(p.m); n != PendingMax {
		t.Fatalf("hay %d pendientes, el tope es %d", n, PendingMax)
	}
	if _, _, ok := p.Take(toks[0]); ok {
		t.Fatal("el más viejo debió ceder su lugar")
	}
	if _, _, ok := p.Take(toks[8]); !ok {
		t.Fatal("el devuelto debe estar")
	}
}
