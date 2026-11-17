package audit

import (
	"context"
	"strings"
	"testing"
)

// verificar exige que Verify no falle con error y devuelva la cadena rota en first.
func verificar(t *testing.T, l *Log, nombre string, first uint64) {
	t.Helper()
	v, err := l.Verify(context.Background())
	if err != nil || v.Intact || v.FirstBroken != first {
		t.Fatalf("%s: verify = %+v, %v (esperaba rota en %d)", nombre, v, err, first)
	}
}

func TestVerifyDetectaEdicionDeCadaCampo(t *testing.T) {
	for _, set := range []string{
		"at='2000-01-01T00:00:00.000000000Z'", "at='no es fecha'", "at=12345", "actor='x'", "action='x'", "target='x'", "detail='x'",
		"prev='" + Genesis + "'", "hash='" + Genesis + "'", "detail=X'ff00fe'", "detail='" + strings.Repeat("é", 32<<10) + "'",
	} {
		l, exec := newLog(t)
		appendN(t, l, 5)
		exec(`DROP TRIGGER audit_log_no_update`)
		exec(`UPDATE audit_log SET ` + set + ` WHERE seq=3`)
		verificar(t, l, set[:min(len(set), 20)], 3)
	}
}

func TestVerifyDetectaSeqEditada(t *testing.T) {
	l, exec := newLog(t)
	appendN(t, l, 5)
	exec(`DROP TRIGGER audit_log_no_update`)
	exec(`UPDATE audit_log SET seq=9 WHERE seq=3`) // hueco: 1,2,4,5,9
	verificar(t, l, "seq editada", 4)
}

func TestVerifyDetectaFilaBorradaEnMedio(t *testing.T) {
	l, exec := newLog(t)
	appendN(t, l, 5)
	exec(`DROP TRIGGER audit_log_no_delete`)
	exec(`DELETE FROM audit_log WHERE seq=3`)
	verificar(t, l, "borrada", 4)
}

func TestVerifyDetectaBorradoDelPrincipio(t *testing.T) {
	l, exec := newLog(t)
	appendN(t, l, 5)
	exec(`DROP TRIGGER audit_log_no_delete`)
	exec(`DELETE FROM audit_log WHERE seq<=2`)
	verificar(t, l, "cabeza", 3)
}

func TestVerifyDetectaFilaDuplicadaYReordenada(t *testing.T) {
	l, exec := newLog(t)
	appendN(t, l, 4)
	exec(`DROP TRIGGER audit_log_no_update`)
	// reordenar: intercambiar el contenido de las filas 2 y 3 (seq se queda, el resto viaja)
	exec(`CREATE TEMP TABLE t AS SELECT * FROM audit_log`)
	exec(`UPDATE audit_log SET at=(SELECT at FROM t WHERE t.seq=3), actor=(SELECT actor FROM t WHERE t.seq=3), action=(SELECT action FROM t WHERE t.seq=3),
		target=(SELECT target FROM t WHERE t.seq=3), detail=(SELECT detail FROM t WHERE t.seq=3), prev=(SELECT prev FROM t WHERE t.seq=3),
		hash=(SELECT hash FROM t WHERE t.seq=3) WHERE seq=2`)
	verificar(t, l, "reordenada", 2)

	l2, exec2 := newLog(t)
	appendN(t, l2, 4)
	exec2(`INSERT INTO audit_log SELECT 5,at,actor,action,target,detail,prev,hash FROM audit_log WHERE seq=4`) // copia exacta de la 4
	verificar(t, l2, "duplicada", 5)

	// seq repetida: la clave primaria lo impide en SQLite.
	if _, err := l2.db.Exec(`INSERT INTO audit_log SELECT 4,at,actor,action,target,detail,prev,hash FROM audit_log WHERE seq=4`); err == nil {
		t.Fatal("la base aceptó una seq repetida")
	}
}

// LÍMITE CONOCIDO, no un defecto que este paquete pueda arreglar: Verify valida una cadena contigua desde 1 y no sabe cuántas
// filas debía haber. Quitar las últimas N filas deja una cadena válida y Intact=true. Solo se nota comparando Head con un
// valor anclado fuera de la base (por ejemplo el de una exportación anterior). Nada la compara automáticamente (manifest.audit_head
// existe, pero quien audita tiene que cotejarlo a mano).
func TestVerifyNoDetectaTruncadoDeCola(t *testing.T) {
	l, exec := newLog(t)
	rs := appendN(t, l, 5)
	ancla := rs[4].Hash // lo que un ancla externa habría guardado
	exec(`DROP TRIGGER audit_log_no_delete`)
	exec(`DELETE FROM audit_log WHERE seq>3`)
	v, err := l.Verify(context.Background())
	if err != nil || !v.Intact {
		t.Fatalf("verify = %+v, %v: el truncado de cola dejó de ser indetectable; actualiza THREAT_MODEL.md", v, err)
	}
	if v.Head == ancla {
		t.Fatal("el Head no cambió")
	}
	if v.Head != rs[2].Hash {
		t.Fatalf("Head = %s", v.Head)
	}
}

func TestVerifyBaseVaciaEsIntacta(t *testing.T) {
	l, _ := newLog(t)
	if v, err := l.Verify(context.Background()); err != nil || !v.Intact || v.Head != Genesis {
		t.Fatalf("%+v %v", v, err)
	}
}
