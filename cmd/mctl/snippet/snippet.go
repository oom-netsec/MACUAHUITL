// Package snippet es el área de mctl para los snippets del modo de cambio asistido (ADR 0007): crear o nombrar una VLAN,
// agregar o quitar una VLAN de un trunk, crear una SVI y las plantillas del catálogo (snippet list y snippet run). Sin --asistido solo imprime el plan y no cambia nada.
package snippet

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"strconv"

	"github.com/oom-netsec/MACUAHUITL/cmd/mctl/cli"
	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
)

const help = `  snippet vlan EQUIPO[:PUERTO] ID --cred ID [--name X | --remove [--accept-trunk]] [--accept-vtp] [--accept HUELLA]... [--write-memory] [--asistido]
  snippet trunk EQUIPO[:PUERTO] IF add|remove VLAN --cred ID [--accept HUELLA]... [--write-memory] [--asistido]
  snippet svi EQUIPO[:PUERTO] VLAN DIRECCION MASCARA --cred ID [--desc T] [--accept HUELLA]... [--write-memory] [--asistido]
  snippet list [--platform P] [--json]
  snippet run EQUIPO[:PUERTO] ID --cred ID [--set campo=valor]... [--accept HUELLA]... [--write-memory] [--asistido]
        (sin --asistido solo muestra el plan con su reversa; con --asistido pide confirmación en cada paso: s/N, r = revertir.
         --remove borra la VLAN (existente, activa, sin puertos, SVI ni trunk nativo; sin --name;
         si viaja por trunks pide --accept-trunk). El trunk solo admite add o remove
         de una VLAN: nunca reemplaza la lista permitida. list muestra el catálogo con los campos de cada plantilla y run la aplica con --set;
         un secreto que no viene en --set se pide por la terminal sin eco)`

type common struct {
	credID            string
	assisted, writeMe bool
	accept            cli.List
}

func (g *common) flags(fs *flag.FlagSet) {
	fs.StringVar(&g.credID, "cred", "", "ID de la credencial")
	fs.BoolVar(&g.assisted, "asistido", false, "aplicar el cambio con confirmación por paso")
	fs.BoolVar(&g.writeMe, "write-memory", false, "agrega el paso final write memory")
	fs.Var(&g.accept, "accept", "huella SHA256 confirmada (repetible)")
}

// vlanNum lee un número de VLAN de 1 a 4094 antes de convertirlo a uint32 (-1 no puede volverse 4294967295).
func vlanNum(s string) (uint32, error) {
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > 4094 {
		return 0, fmt.Errorf("VLAN %q: las VLAN van de 1 a 4094", s)
	}
	return uint32(n), nil
}

// plan pide el plan, lo muestra y, con --asistido, lo ejecuta paso a paso.
func plan(c *cli.Env, host string, g *common, set func(*v1.PlanSnippetRequest)) error {
	addr, port, err := cli.SplitHost(host)
	if err != nil {
		return err
	}
	req := &v1.PlanSnippetRequest{Target: &v1.AssistTarget{Name: addr, Address: addr, Port: port, CredentialId: g.credID},
		WriteMemory: g.writeMe, AcceptedHostKeyFingerprints: g.accept}
	set(req)
	cl := v1.NewAssistServiceClient(c.Conn)
	res, err := cl.PlanSnippet(context.Background(), req)
	if err != nil {
		return err
	}
	cli.PrintPlan(c.Out, res.Plan)
	if !g.assisted {
		fmt.Fprintln(c.Out, "\nSolo se mostró el plan: no se cambió nada. Para aplicarlo agrega --asistido.")
		return nil
	}
	run, err := cl.StartRun(context.Background(), &v1.StartRunRequest{PlanId: res.PlanId, Assisted: true})
	if err != nil {
		return err
	}
	fmt.Fprintf(c.Out, "\nMODO ASISTIDO ACTIVO. Ejecución %s: cada paso que cambia la red pide confirmación.\n", run.RunId)
	return cli.Follow(c, cl, run.RunId, 0, nil)
}

func vlan(c *cli.Env, args []string) error {
	var g common
	var name string
	var vtp, remove, trunk bool
	fs, err := cli.Flags("snippet vlan", args, func(fs *flag.FlagSet) {
		g.flags(fs)
		fs.StringVar(&name, "name", "", "nombre de la VLAN")
		fs.BoolVar(&remove, "remove", false, "borra la VLAN (sin puertos asignados; no lleva --name)")
		fs.BoolVar(&trunk, "accept-trunk", false, "con --remove, acepta borrar una VLAN que viaja por trunks")
		fs.BoolVar(&vtp, "accept-vtp", false, "acepta que el cambio se propague por VTP")
	})
	if err != nil || fs.NArg() != 2 || g.credID == "" {
		return errors.New("uso: mctl snippet vlan EQUIPO[:PUERTO] ID --cred ID [--name X | --remove [--accept-trunk]] [--accept-vtp] [--asistido]")
	}
	id, err := vlanNum(fs.Arg(1))
	if err != nil {
		return err
	}
	return plan(c, fs.Arg(0), &g, func(r *v1.PlanSnippetRequest) {
		r.Snippet = &v1.PlanSnippetRequest_Vlan{Vlan: &v1.VlanSnippet{Id: id, Name: name, AcceptVtp: vtp, Remove: remove, AcceptTrunk: trunk}}
	})
}

func trunk(c *cli.Env, args []string) error {
	var g common
	fs, err := cli.Flags("snippet trunk", args, g.flags)
	if err != nil || fs.NArg() != 4 || g.credID == "" {
		return errors.New("uso: mctl snippet trunk EQUIPO[:PUERTO] IF add|remove VLAN --cred ID [--asistido]")
	}
	op := fs.Arg(2)
	if op != "add" && op != "remove" { // nunca se reemplaza la lista: ni "set" ni una lista como 10,20
		return errors.New("la operación es add o remove: el trunk nunca reemplaza su lista de VLAN permitidas")
	}
	v, err := vlanNum(fs.Arg(3))
	if err != nil {
		return err
	}
	return plan(c, fs.Arg(0), &g, func(r *v1.PlanSnippetRequest) {
		r.Snippet = &v1.PlanSnippetRequest_Trunk{Trunk: &v1.TrunkSnippet{Interface: fs.Arg(1), Op: op, Vlan: v}}
	})
}

func svi(c *cli.Env, args []string) error {
	var g common
	var desc string
	fs, err := cli.Flags("snippet svi", args, func(fs *flag.FlagSet) {
		g.flags(fs)
		fs.StringVar(&desc, "desc", "", "descripción")
	})
	if err != nil || fs.NArg() != 4 || g.credID == "" {
		return errors.New("uso: mctl snippet svi EQUIPO[:PUERTO] VLAN DIRECCION MASCARA --cred ID [--desc T] [--asistido]")
	}
	v, err := vlanNum(fs.Arg(1))
	if err != nil {
		return err
	}
	set := false
	fs.Visit(func(f *flag.Flag) { set = set || f.Name == "desc" })
	return plan(c, fs.Arg(0), &g, func(r *v1.PlanSnippetRequest) {
		s := &v1.SviSnippet{Vlan: v, Address: fs.Arg(2), Mask: fs.Arg(3)}
		if set {
			s.Description = &desc
		}
		r.Snippet = &v1.PlanSnippetRequest_Svi{Svi: s}
	})
}

// Area registra snippet vlan|trunk|svi.
func Area() cli.Area {
	return cli.Area{Usage: help, Commands: []cli.Command{{Name: "snippet vlan", Run: vlan}, {Name: "snippet trunk", Run: trunk}, {Name: "snippet svi", Run: svi},
		{Name: "snippet list", Run: list}, {Name: "snippet run", Run: run}}}
}
