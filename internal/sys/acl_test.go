package sys

import "testing"

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
