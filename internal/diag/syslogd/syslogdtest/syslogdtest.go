// Package syslogdtest manda datagramas a un receptor syslog de prueba; existe
// porque noegress no deja importar "net" fuera de internal/diag.
package syslogdtest

import "net"

// SendUDP manda n copias de msg a addr.
func SendUDP(addr, msg string, n int) error {
	c, err := net.Dial("udp", addr)
	if err != nil {
		return err
	}
	defer c.Close()
	for range n {
		if _, err := c.Write([]byte(msg)); err != nil {
			return err
		}
	}
	return nil
}
