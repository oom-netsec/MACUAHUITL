// Package credrotate es el área de mctl para rotar la contraseña de un usuario local con el modo de cambio asistido (ADR 0007).
// El secreto nuevo se lee sin eco (terminal o stdin), nunca por argumentos, y no se imprime en ningún momento.
package credrotate

import (
	"context"
	"errors"
	"flag"
	"fmt"

	"github.com/oom-netsec/MACUAHUITL/cmd/mctl/cli"
	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
)

const help = `  cred rotate EQUIPO[:PUERTO] --user U --cred ID [--update-cred ID] [--generate] [--accept HUELLA]... [--asistido]
        (rota el secreto de un usuario local de un equipo; --cred es la credencial con la que te conectas y debe ser de OTRO usuario;
         el secreto nuevo se lee de la terminal o de stdin, o con --generate lo crea el núcleo (exige --update-cred); si la sesión nueva
         entra, se pide write memory (obligatorio: sin él el equipo vuelve al hash anterior al reiniciar); solo si sale [OK],
         --update-cred deja el secreto en la bóveda y la credencial anterior se conserva como "<etiqueta> (anterior)";
         si la sesión nueva no entra o rechazas write memory, se propone la reversa por la sesión original)`

func rotate(c *cli.Env, args []string) error {
	var user, credID, update string
	var gen, assisted bool
	var accept cli.List
	fs, err := cli.Flags("cred rotate", args, func(fs *flag.FlagSet) {
		fs.StringVar(&user, "user", "", "usuario local a rotar")
		fs.StringVar(&credID, "cred", "", "ID de la credencial con la que te conectas")
		fs.StringVar(&update, "update-cred", "", "ID de la credencial de la bóveda que recibe el secreto nuevo")
		fs.BoolVar(&gen, "generate", false, "que el núcleo genere el secreto")
		fs.BoolVar(&assisted, "asistido", false, "aplicar el cambio con confirmación por paso")
		fs.Var(&accept, "accept", "huella SHA256 confirmada (repetible)")
	})
	if err != nil || fs.NArg() != 1 || user == "" || credID == "" {
		return errors.New("uso: mctl cred rotate EQUIPO[:PUERTO] --user U --cred ID [--update-cred ID] [--generate] [--asistido]")
	}
	if gen && update == "" {
		return cli.Err("mctl.credrotate.generate")
	}
	host, port, err := cli.SplitHost(fs.Arg(0))
	if err != nil {
		return err
	}
	req := &v1.PlanCredRotateRequest{Target: &v1.AssistTarget{Name: host, Address: host, Port: port, CredentialId: credID}, User: user,
		UpdateCredentialId: update, WriteMemory: true, // write memory es obligatorio en la rotación
		AcceptedHostKeyFingerprints: accept}
	if !gen {
		b, err := c.Secret(cli.T("mctl.credrotate.prompt", "user", user))
		if err != nil {
			return err
		}
		req.NewSecret = string(b)
		cli.Wipe(b)
	}
	cl := v1.NewAssistServiceClient(c.Conn)
	res, err := cl.PlanCredRotate(context.Background(), req)
	req.NewSecret = ""
	if err != nil {
		return err
	}
	cli.PrintPlan(c.Out, res.Plan)
	fmt.Fprintln(c.Out, "\n"+cli.T("mctl.credrotate.note_1"))
	fmt.Fprintln(c.Out, cli.T("mctl.credrotate.note_2"))
	fmt.Fprintln(c.Out, cli.T("mctl.credrotate.note_3"))
	fmt.Fprintln(c.Out, cli.T("mctl.credrotate.note_4"))
	if !assisted {
		fmt.Fprintln(c.Out, cli.T("mctl.restore.plan_only"))
		return nil
	}
	run, err := cl.StartRun(context.Background(), &v1.StartRunRequest{PlanId: res.PlanId, Assisted: true})
	if err != nil {
		return err
	}
	fmt.Fprintln(c.Out, "\n"+cli.T("mctl.restore.assist_active", "run", run.RunId))
	return cli.Follow(c, cl, run.RunId, 0, nil)
}

// Area registra cred rotate.
func Area() cli.Area {
	return cli.Area{Usage: help, Commands: []cli.Command{{Name: "cred rotate", Run: rotate}}}
}
