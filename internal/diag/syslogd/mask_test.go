package syslogd

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// M3: el receptor enmascara cada mensaje antes de escribirlo o emitirlo (archivo, consola y OnMessage).
func TestReceptorEnmascaraSecretos(t *testing.T) {
	dir := t.TempDir()
	s := &sink{}
	ctx, cancel := context.WithCancel(context.Background())
	addr := make(chan string, 1)
	done := make(chan error, 1)
	go func() {
		done <- Listen(ctx, Config{Addr: "127.0.0.1:0", Proto: "udp", Out: s, OnMessage: s.on,
			Sink:        &Sink{Dir: dir, Template: "t_{fecha}", MaxFiles: 5, Format: "crudo"},
			OnListening: func(a string) { addr <- a }})
	}()
	c, err := net.Dial("udp", <-addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	msgs := []string{
		`<189>Nov 15 10:00:00 R1 %PARSER-5-CFGLOG_LOGGEDCMD: User:admin  logged command:snmp-server community SYSLEAK1 RO`,
		`<189>Nov 15 10:00:01 R1 %PARSER-5-CFGLOG_LOGGEDCMD: User:admin  logged command:key SYSLEAK2`,
		`<165>Nov 15 10:00:02 asa %ASA-5-111008: User 'admin' executed the 'enable password SYSLEAK3 level 15' command.`,
		`<165>Nov 15 10:00:03 asa %ASA-5-111010: User 'admin', running 'CLI' from IP 10.0.0.1, executed 'username bob password SYSLEAK4'`,
	}
	for _, m := range msgs {
		c.Write([]byte(m))
	}
	got := s.wait(t, len(msgs))
	cancel()
	<-done
	files, _ := filepath.Glob(filepath.Join(dir, "*"))
	var disk strings.Builder
	for _, f := range files {
		b, _ := os.ReadFile(f)
		disk.Write(b)
	}
	s.mu.Lock()
	console := s.buf.String()
	s.mu.Unlock()
	all := console + disk.String()
	for _, m := range got {
		all += m.Raw + m.Text
	}
	for _, leak := range []string{"SYSLEAK1", "SYSLEAK2", "SYSLEAK3", "SYSLEAK4"} {
		if strings.Contains(all, leak) {
			t.Errorf("se filtró %s:\n%s", leak, all)
		}
	}
	if !strings.Contains(all, "<MASKED:") || disk.Len() == 0 {
		t.Errorf("no enmascaró o no escribió:\n%s", all)
	}
	// Un mensaje sin secreto llega igual.
	if got[0].Mnemonic != "PARSER-5-CFGLOG_LOGGEDCMD" {
		t.Errorf("se perdió el mnemónico: %+v", got[0])
	}
}
