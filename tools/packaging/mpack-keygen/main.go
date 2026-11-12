// mpack-keygen genera la llave Ed25519 que firma los paquetes oficiales (ADR 0010).
//
// La privada (64 bytes de ed25519.PrivateKey en base64, una línea) va al archivo de -priv con permisos 0600
// y nunca se imprime; es lo que se guarda en el secret MPACK_SIGNING_KEY y en el respaldo fuera de línea.
// La pública (32 bytes en base64, una línea) va a -pub, que se sube al repo.
// No pisa archivos existentes: rotar la llave es una decisión explícita (borra primero).
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	priv := flag.String("priv", "", "archivo de la llave privada (fuera del repo)")
	pub := flag.String("pub", "internal/pack/oom.pub", "archivo de la llave pública")
	flag.Parse()
	if *priv == "" {
		fmt.Fprintln(os.Stderr, "uso: mpack-keygen -priv <archivo fuera del repo> [-pub internal/pack/oom.pub]")
		os.Exit(2)
	}
	if err := run(*priv, *pub); err != nil {
		fmt.Fprintln(os.Stderr, "mpack-keygen:", err)
		os.Exit(1)
	}
	fmt.Printf("llave privada en %s (0600); llave pública en %s\n", *priv, *pub)
}

func run(privPath, pubPath string) error {
	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	// Prueba de humo: lo que se escribe tiene que firmar y verificar.
	if msg := []byte("mpack"); !ed25519.Verify(pk, msg, ed25519.Sign(sk, msg)) {
		return fmt.Errorf("la llave generada no verifica")
	}
	if err := os.MkdirAll(filepath.Dir(privPath), 0o700); err != nil {
		return err
	}
	if err := escribe(privPath, sk, 0o600); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(pubPath), 0o755); err != nil {
		return err
	}
	if err := escribe(pubPath, pk, 0o644); err != nil {
		os.Remove(privPath) // sin pública la privada no sirve; no dejes una a medias
		return err
	}
	return verifica(privPath, pubPath)
}

func escribe(path string, key []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(base64.StdEncoding.EncodeToString(key) + "\n"); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// verifica relee ambos archivos: la pública tiene que ser la mitad pública de la privada.
func verifica(privPath, pubPath string) error {
	lee := func(p string, n int) ([]byte, error) {
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		k, err := base64.StdEncoding.DecodeString(string(bytes.TrimSpace(b)))
		if err != nil || len(k) != n {
			return nil, fmt.Errorf("%s: llave mal formada", p)
		}
		return k, nil
	}
	sk, err := lee(privPath, ed25519.PrivateKeySize)
	if err != nil {
		return err
	}
	pk, err := lee(pubPath, ed25519.PublicKeySize)
	if err != nil {
		return err
	}
	if !bytes.Equal(ed25519.PrivateKey(sk).Public().(ed25519.PublicKey), pk) {
		return fmt.Errorf("la llave pública no corresponde a la privada")
	}
	return nil
}
