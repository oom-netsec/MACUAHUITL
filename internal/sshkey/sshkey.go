// Package sshkey comprueba que una llave privada SSH se puede leer con x/crypto/ssh, igual que transport.OpenSSH al conectar.
//
// Existe aparte para que vault y core la validen sin importar x/crypto/ssh (noegress lo prohíbe fuera de la lista de permitidos):
// este paquete solo llama a ParsePrivateKey, no abre sockets. No hace: conectar, ni guardar nada.
package sshkey

import "golang.org/x/crypto/ssh"

// Parse devuelve error si key no es una llave privada que x/crypto/ssh pueda usar sin frase (una con frase tampoco sirve a transport).
func Parse(key []byte) error {
	_, err := ssh.ParsePrivateKey(key)
	return err
}
