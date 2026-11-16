package sys

import (
	"errors"
	"testing"
)

const (
	sidUser   = "S-1-5-21-1-2-3-1001"
	sidOtro   = "S-1-5-21-1-2-3-1002"
	sidUsers  = "S-1-5-32-545"
	sidEvery  = "S-1-1-0"
	sidAuthed = "S-1-5-11"
)

func TestForeignSID(t *testing.T) {
	propias := []ace{{sid: sidUser, mask: fileAllAccess}, {sid: sidSystem, mask: fileAllAccess}, {sid: sidAdmins, mask: fileAllAccess}}
	casos := []struct {
		nombre string
		aces   []ace
		mask   uint32
		skipIO bool
		ign    []string
		want   string
	}{
		{"solo propias", propias, anyAccess, false, nil, ""},
		{"Usuarios con lectura", append(propias[:3:3], ace{sid: sidUsers, mask: 0x120089}), anyAccess, false, nil, sidUsers},
		{"ACE heredable de otro cuenta aunque sea solo-herencia", append(propias[:3:3], ace{sid: sidOtro, mask: 1, inheritOnly: true}), anyAccess, false, nil, sidOtro},
		{"solo-herencia se salta en ancestros", []ace{{sid: sidEvery, mask: fileAllAccess, inheritOnly: true}}, writeMask, true, nil, ""},
		{"Everyone escribe", []ace{{sid: sidEvery, mask: 0x1301BF}}, writeMask, true, nil, sidEvery},
		{"Everyone con Write (agrega archivos)", []ace{{sid: sidEvery, mask: 0x100116}}, writeMask, true, nil, sidEvery},
		{"Everyone solo lee", []ace{{sid: sidEvery, mask: 0x1200A9}}, writeMask, true, nil, ""},
		{"Autenticados solo agregan subcarpeta (raíz de C:)", []ace{{sid: sidAuthed, mask: fileAddSubdir}}, writeMask, true, nil, ""},
		{"TrustedInstaller en C:\\Windows", []ace{{sid: sidTrustedInstaller, mask: fileAllAccess}}, writeMask, true, ancestorIgnore, ""},
		{"ignorado", []ace{{sid: sidCreatorOwner, mask: fileAllAccess}}, writeMask, true, []string{sidCreatorOwner}, ""},
	}
	for _, c := range casos {
		if got := foreignSID(c.aces, sidUser, c.mask, c.skipIO, c.ign...); got != c.want {
			t.Errorf("%s: foreignSID = %q, quería %q", c.nombre, got, c.want)
		}
	}
}

func TestIsPrivateACL(t *testing.T) {
	propias := []ace{{sid: sidUser, mask: fileAllAccess}, {sid: sidSystem, mask: fileAllAccess}, {sid: sidAdmins, mask: fileAllAccess}}
	if !isPrivateACL(sidUser, sidUser, true, propias) {
		t.Fatal("la DACL propia debía ser privada")
	}
	if isPrivateACL(sidUser, sidUser, false, propias) {
		t.Fatal("sin protección (hereda) no es privada")
	}
	if isPrivateACL(sidOtro, sidUser, true, propias) {
		t.Fatal("dueño ajeno no es privado")
	}
	if isPrivateACL(sidUser, sidUser, true, append(propias[:3:3], ace{sid: sidUsers, mask: 1})) {
		t.Fatal("ACE para Usuarios no es privada")
	}
}

func TestIgnoreUnsupported(t *testing.T) {
	boom := errors.New("boom")
	if err := ignoreUnsupported(errors.Join(errors.ErrUnsupported, boom)); err != nil {
		t.Fatalf("un FS sin ACL no debe fallar: %v", err)
	}
	if err := ignoreUnsupported(boom); err != boom {
		t.Fatalf("otro error debe pasar: %v", err)
	}
	if ignoreUnsupported(nil) != nil {
		t.Fatal("nil")
	}
}

// Cada bit de writeMask por separado en un ancestro de Everyone: si se quita uno de la máscara, esta prueba falla.
func TestWriteMaskBitAPorBit(t *testing.T) {
	bits := map[string]uint32{"ADD_FILE": fileAddFile, "DELETE_CHILD": fileDeleteChild, "DELETE": deleteRight,
		"WRITE_DAC": writeDAC, "WRITE_OWNER": writeOwner, "GENERIC_ALL": genericAll, "GENERIC_WRITE": genericWrite}
	for nombre, b := range bits {
		if got := foreignSID([]ace{{sid: sidEvery, mask: b}}, sidUser, writeMask, true); got != sidEvery {
			t.Errorf("%s (%#x) no cuenta como escritura en un ancestro", nombre, b)
		}
	}
	if writeMask != fileAddFile|fileDeleteChild|deleteRight|writeDAC|writeOwner|genericAll|genericWrite {
		t.Errorf("writeMask tiene bits que esta prueba no cubre: %#x", uint32(writeMask))
	}
}

func TestForeignSIDsDevuelveTodos(t *testing.T) {
	aces := []ace{{sid: sidUser, mask: 1}, {sid: sidUsers, mask: 1}, {sid: sidEvery, mask: 1}, {sid: sidUsers, mask: 2}}
	if got := foreignSIDs(aces, sidUser, anyAccess, false); len(got) != 2 || got[0] != sidUsers || got[1] != sidEvery {
		t.Fatalf("foreignSIDs = %v", got)
	}
}

func TestAceFromRaw(t *testing.T) {
	casos := []struct {
		nombre string
		typ    uint8
		want   ace
		ok     bool
	}{
		{"permitir", 0x0, ace{sid: sidUsers, mask: 7, flags: 3}, true},
		{"permitir condicional cuenta como permitir", 0x9, ace{sid: sidUsers, mask: 7, flags: 3}, true},
		{"negar", 0x1, ace{}, false},
		{"negar de objeto", 0x6, ace{}, false},
		{"negar condicional", 0xA, ace{}, false},
		{"negar condicional de objeto", 0xC, ace{}, false},
		{"permitir de objeto: falla cerrado", 0x5, ace{sid: "tipo-ace-5", mask: anyAccess, flags: 3}, true},
		{"desconocido: falla cerrado", 0x42, ace{sid: "tipo-ace-66", mask: anyAccess, flags: 3}, true},
	}
	for _, c := range casos {
		got, ok := aceFromRaw(c.typ, 3, 7, sidUsers)
		if ok != c.ok || got != c.want {
			t.Errorf("%s: %+v, %v", c.nombre, got, ok)
		}
	}
	if a, _ := aceFromRaw(0, aceInheritOnly, 7, sidUsers); !a.inheritOnly {
		t.Error("inheritOnly no se copia")
	}
}

func TestOwnerAcceptable(t *testing.T) {
	if !ownerAcceptable(sidUser, sidUser) || !ownerAcceptable(sidAdmins, sidUser) {
		t.Fatal("el usuario y Administradores se aceptan como dueño previo")
	}
	if ownerAcceptable(sidOtro, sidUser) || ownerAcceptable(sidSystem, sidUser) {
		t.Fatal("otro dueño no se acepta")
	}
}

func TestAllInherit(t *testing.T) {
	ok := []ace{{sid: sidUser, flags: aceOI | aceCI}, {sid: sidSystem, flags: aceOI | aceCI}}
	if !allInherit(ok) {
		t.Fatal("OI|CI en todas debía pasar")
	}
	if allInherit(append(ok[:2:2], ace{sid: sidAdmins, flags: aceCI})) || allInherit(append(ok[:2:2], ace{sid: sidAdmins})) || allInherit(nil) {
		t.Fatal("falta OI o CI, o no hay ACE: se reaplica")
	}
}

func TestRequireAbs(t *testing.T) {
	for _, p := range []string{"", "rel", "./x", "a/b"} {
		if requireAbs(p) == nil {
			t.Errorf("%q no es absoluta y se aceptó", p)
		}
	}
	if requireAbs(absForTest) != nil {
		t.Error("una ruta absoluta se rechazó")
	}
}

func TestPrivateSDDL(t *testing.T) {
	want := "O:" + sidUser + "D:P(A;;FA;;;" + sidUser + ")(A;;FA;;;SY)(A;;FA;;;BA)"
	if got := privateSDDL(sidUser); got != want {
		t.Fatalf("privateSDDL = %q", got)
	}
}

// Los valores son los de winnt.h: la prueba por bit usa los símbolos y no vería un valor cambiado.
func TestValoresDeWinnt(t *testing.T) {
	for nombre, par := range map[string][2]uint32{"ADD_FILE": {fileAddFile, 0x2}, "ADD_SUBDIR": {fileAddSubdir, 0x4}, "DELETE_CHILD": {fileDeleteChild, 0x40},
		"DELETE": {deleteRight, 0x10000}, "WRITE_DAC": {writeDAC, 0x40000}, "WRITE_OWNER": {writeOwner, 0x80000},
		"GENERIC_ALL": {genericAll, 0x10000000}, "GENERIC_WRITE": {genericWrite, 0x40000000}, "FILE_ALL_ACCESS": {fileAllAccess, 0x1F01FF},
		"OI": {aceOI, 1}, "CI": {aceCI, 2}, "INHERIT_ONLY": {aceInheritOnly, 8}} {
		if par[0] != par[1] {
			t.Errorf("%s = %#x, winnt.h dice %#x", nombre, par[0], par[1])
		}
	}
}
