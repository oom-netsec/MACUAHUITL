package listen

import "testing"

func TestValidateAddr(t *testing.T) {
	for addr, ok := range map[string]bool{"127.0.0.1:1162": true, "127.0.0.1:0": true, "127.0.0.1:162": false, "0.0.0.0:1162": false,
		"[::]:2055": false, "localhost:1162": false, "127.0.0.1": false, "10.0.0.5:6343": true} {
		if err := ValidateAddr(addr, false); (err == nil) != ok {
			t.Errorf("%s: err = %v", addr, err)
		}
	}
	if err := ValidateAddr("0.0.0.0:1162", true); err != nil {
		t.Fatal(err)
	}
}
