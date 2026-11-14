package playbook

import (
	"io/fs"
	"reflect"
	"testing"
	"testing/fstest"
	"time"
)

// Marshal escribe un YAML que Load vuelve a leer idéntico (timeouts, may_contain_secrets, platforms y params incluidos).
func TestMarshalIdaYVuelta(t *testing.T) {
	src := `id: x
platform: wlc-9800
name: Uno
name_en: One
pre: [terminal length 0]
params:
  - name: mac
    kind: mac
commands:
  - cmd: show wireless client mac-address {mac} detail
    timeout: 3m
  - cmd: show clock
    may_contain_secrets: true
    platforms: [ios-xe]
`
	a, err := Load(fs.FS(fstest.MapFS{"x.yaml": {Data: []byte(src)}}))
	if err != nil || len(a) != 1 {
		t.Fatal(err)
	}
	b, err := Marshal(a[0])
	if err != nil {
		t.Fatal(err)
	}
	c, err := Load(fs.FS(fstest.MapFS{"x.yaml": {Data: b}}))
	if err != nil || !reflect.DeepEqual(a, c) {
		t.Fatalf("%v\n%+v\n%+v\n%s", err, a, c, b)
	}
	if a[0].Commands[0].Timeout != 3*time.Minute {
		t.Fatal("timeout")
	}
}
