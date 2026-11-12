package fileserve

import "testing"

func FuzzParseRequest(f *testing.F) {
	f.Add(rrq("running-config"))
	f.Add(wrq("x", "blksize", "1428", "tsize", "0"))
	f.Add([]byte{})
	f.Add([]byte{0, 2, 'a', 0, 'o', 'c', 't', 'e', 't'})
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := parseRequest(b)
		if err != nil {
			return
		}
		if r.op != opRRQ && r.op != opWRQ {
			t.Fatalf("op %d", r.op)
		}
		// Lo que el servidor haría después con el nombre nunca debe entrar en pánico ni escapar.
		if name, err := SafeName(r.file); err == nil && (name == "" || name == ".." || name == ".") {
			t.Fatalf("SafeName dejó pasar %q", name)
		}
	})
}

func FuzzSafeName(f *testing.F) {
	for _, s := range []string{"a", "../../x", "a/b", "", "..", "\x00"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		n, err := SafeName(in)
		if err != nil {
			return
		}
		for _, r := range n {
			if r == '/' || r == '\\' || r < 0x20 {
				t.Fatalf("%q -> %q", in, n)
			}
		}
		if n == "" || n == "." || n == ".." {
			t.Fatalf("%q -> %q", in, n)
		}
	})
}
