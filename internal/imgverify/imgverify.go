// Package imgverify calcula MD5 y SHA-512 de una imagen y los compara con los que
// publica Cisco en su sitio de descargas. También arma el comando para repetir la
// verificación en el equipo después de copiarla.
package imgverify

import (
	"crypto/md5"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type Result struct {
	File          string
	Size          int64
	MD5           string
	SHA512        string
	MD5Match      string `json:",omitempty"` // ok, distinto o vacío si no se pegó un valor
	SHA512Match   string `json:",omitempty"`
	VerifyCommand string
}

// OK es falso si algún valor esperado no coincide.
func (r Result) OK() bool { return r.MD5Match != "distinto" && r.SHA512Match != "distinto" }

func normalize(v string, hexLen int, name string) (string, error) {
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "" {
		return "", nil
	}
	if b, err := hex.DecodeString(v); err != nil || len(b)*2 != hexLen {
		return "", fmt.Errorf("imgverify: el %s esperado debe tener %d dígitos hexadecimales", name, hexLen)
	}
	return v, nil
}

func match(want, got string) string {
	switch {
	case want == "":
		return ""
	case want == got:
		return "ok"
	}
	return "distinto"
}

// Check lee el archivo una sola vez y calcula ambos resúmenes.
func Check(path, wantMD5, wantSHA512 string) (Result, error) {
	if !filepath.IsAbs(path) {
		return Result{}, errors.New("imgverify: la ruta debe ser absoluta")
	}
	m, err := normalize(wantMD5, 32, "MD5")
	if err != nil {
		return Result{}, err
	}
	s, err := normalize(wantSHA512, 128, "SHA-512")
	if err != nil {
		return Result{}, err
	}
	f, err := os.Open(path)
	if err != nil {
		return Result{}, fmt.Errorf("imgverify: %w", err)
	}
	defer f.Close()
	h5, h512 := md5.New(), sha512.New()
	n, err := io.Copy(io.MultiWriter(h5, h512), f)
	if err != nil {
		return Result{}, fmt.Errorf("imgverify: %w", err)
	}
	r := Result{File: filepath.Base(path), Size: n, MD5: hex.EncodeToString(h5.Sum(nil)), SHA512: hex.EncodeToString(h512.Sum(nil))}
	r.MD5Match, r.SHA512Match = match(m, r.MD5), match(s, r.SHA512)
	// Sintaxis de IOS/IOS-XE; en NX-OS es «show file bootflash:ARCHIVO md5sum». Sin validar en laboratorio.
	r.VerifyCommand = fmt.Sprintf("verify /md5 flash:%s %s", r.File, r.MD5)
	return r, nil
}
