package diag

import "testing"

// El argv lleva la IP que se pasó (Build no sabe de nombres), en Linux y en Windows.
func TestArgvLlevaLaIP(t *testing.T) {
	for _, tool := range []Tool{Ping, Traceroute} {
		for _, win := range []bool{false, true} {
			_, argv, err := build(Request{Tool: tool, Targets: []string{"2001:db8::1"}}, win)
			if err != nil || argv[len(argv)-1] != "2001:db8::1" {
				t.Errorf("%s win=%v: %q %v", tool, win, argv, err)
			}
		}
	}
}
