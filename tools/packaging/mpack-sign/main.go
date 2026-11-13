// mpack-sign arma y firma los paquetes oficiales para el release (ADR 0010).
//
// Por cada carpeta packs/<nombre>/ la valida con las reglas del instalador, la firma con la llave privada de la
// variable MPACK_SIGNING_KEY (base64 de ed25519.PrivateKey, como la escribe mpack-keygen) y la vuelve a verificar
// como lo haría el núcleo con las llaves oficiales compiladas: si el secret no corresponde a internal/pack/oom.pub,
// falla aquí y no en la máquina del usuario. Deja <editor>-<nombre>-<versión>.mpack y su README en -out.
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/oom-netsec/MACUAHUITL/internal/pack"
)

func main() {
	src := flag.String("packs", "packs", "carpeta con las fuentes packs/<nombre>/")
	out := flag.String("out", "dist", "carpeta de salida")
	core := flag.String("core", "", "versión del núcleo del release, sin v (p. ej. 0.3.0)")
	flag.Parse()
	priv, err := llave(os.Getenv("MPACK_SIGNING_KEY"))
	if err == nil && *core == "" {
		err = fmt.Errorf("falta -core")
	}
	if err == nil {
		var hechos []string
		if hechos, err = firmaTodos(*src, *out, strings.TrimPrefix(*core, "v"), priv, pack.OfficialKeys()); err == nil {
			for _, h := range hechos {
				fmt.Println(h)
			}
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "mpack-sign:", err)
		os.Exit(1)
	}
}

func llave(b64 string) (ed25519.PrivateKey, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil || len(b) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("MPACK_SIGNING_KEY ausente o mal formada") // nunca se cita el valor
	}
	return b, nil
}

func firmaTodos(src, out, core string, priv ed25519.PrivateKey, oficiales []ed25519.PublicKey) ([]string, error) {
	dirs, err := os.ReadDir(src)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		return nil, err
	}
	var hechos []string
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		nombre, err := firma(filepath.Join(src, d.Name()), out, core, priv, oficiales)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", d.Name(), err)
		}
		hechos = append(hechos, nombre)
	}
	if len(hechos) == 0 {
		return nil, fmt.Errorf("no hay paquetes en %s", src)
	}
	return hechos, nil
}

func firma(dir, out, core string, priv ed25519.PrivateKey, oficiales []ed25519.PublicKey) (string, error) {
	if _, err := pack.ValidateSource(dir, core); err != nil {
		return "", err
	}
	files, err := pack.ReadSource(dir)
	if err != nil {
		return "", err
	}
	pack.Sign(files, priv)
	data, err := pack.Zip(files)
	if err != nil {
		return "", err
	}
	p, err := pack.Verify(data, core, oficiales)
	if err != nil {
		return "", err
	}
	if !p.Official {
		return "", fmt.Errorf("la firma no valida con la llave oficial (internal/pack/oom.pub): ¿el secret es otra llave?")
	}
	base := strings.ReplaceAll(p.ID, "/", "-") + "-" + p.Version
	if err := os.WriteFile(filepath.Join(out, base+".mpack"), data, 0o644); err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(out, base+".README.md"), []byte(p.Readme), 0o644); err != nil {
		return "", err
	}
	return base + ".mpack", nil
}
