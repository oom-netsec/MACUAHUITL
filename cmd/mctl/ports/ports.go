// Package ports es el área de mctl para aprovisionar puertos de acceso con el modo de cambio
// asistido (ADR 0007). Sin --asistido solo imprime el plan y no cambia nada.
package ports

import (
	"context"
	"errors"
	"flag"
	"fmt"

	"github.com/oom-netsec/MACUAHUITL/cmd/mctl/cli"
	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
)

const help = `  ports set EQUIPO[:PUERTO] IF... --cred ID [--vlan N] [--voice N] [--desc T] [--shut|--no-shut]
        [--accept HUELLA]... [--write-memory] [--asistido]
        (sin --asistido solo muestra el plan con su reversa; con --asistido pide confirmación en cada paso: s/N, r = revertir;
         Ctrl-C aborta la ejecución y avisa si quedó algún equipo cambiado)
  ports runs [--activas]            ejecuciones que el núcleo recuerda (para retomar una que quedó viva)
  ports resume EJECUCION            retoma la confirmación de una ejecución viva`

func set(c *cli.Env, args []string) error {
	var vlan, voice int
	var desc, credID string
	var shut, noShut, assisted, writeMem bool
	var accept cli.List
	fs, err := cli.Flags("ports set", args, func(fs *flag.FlagSet) {
		fs.IntVar(&vlan, "vlan", 0, "VLAN de acceso")
		fs.IntVar(&voice, "voice", 0, "VLAN de voz")
		fs.StringVar(&desc, "desc", "", "descripción (vacía = quitarla)")
		fs.BoolVar(&shut, "shut", false, "apagar el puerto")
		fs.BoolVar(&noShut, "no-shut", false, "encender el puerto")
		fs.StringVar(&credID, "cred", "", "ID de la credencial")
		fs.BoolVar(&assisted, "asistido", false, "aplicar el cambio con confirmación por paso")
		fs.BoolVar(&writeMem, "write-memory", false, "agrega el paso final write memory")
		fs.Var(&accept, "accept", "huella SHA256 confirmada (repetible)")
	})
	const usage = "uso: mctl ports set EQUIPO[:PUERTO] IF... --cred ID [--vlan N] [--voice N] [--desc T] [--shut|--no-shut] [--asistido]"
	if err != nil || fs.NArg() < 2 || credID == "" {
		return errors.New(usage)
	}
	if shut && noShut {
		return errors.New("--shut y --no-shut son excluyentes")
	}
	host, port, err := cli.SplitHost(fs.Arg(0))
	if err != nil {
		return err
	}
	if vlan < 0 || vlan > 4094 || voice < 0 || voice > 4094 { // antes de convertir a uint32: -1 no puede volverse 4294967295
		return errors.New("las VLAN van de 1 a 4094")
	}
	req := &v1.PlanPortsRequest{
		Target:     &v1.AssistTarget{Name: host, Address: host, Port: port, CredentialId: credID},
		Interfaces: fs.Args()[1:], Vlan: uint32(vlan), Voice: uint32(voice), WriteMemory: writeMem,
		AcceptedHostKeyFingerprints: accept,
	}
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "desc":
			req.Description = &desc
		case "shut":
			req.Shutdown = &shut
		case "no-shut":
			off := false
			req.Shutdown = &off
		}
	})
	cl := v1.NewAssistServiceClient(c.Conn)
	plan, err := cl.PlanPorts(context.Background(), req)
	if err != nil {
		return err
	}
	cli.PrintPlan(c.Out, plan.Plan)
	if !assisted {
		fmt.Fprintln(c.Out, "\nSolo se mostró el plan: no se cambió nada. Para aplicarlo agrega --asistido.")
		return nil
	}
	run, err := cl.StartRun(context.Background(), &v1.StartRunRequest{PlanId: plan.PlanId, Assisted: true})
	if err != nil {
		return err
	}
	fmt.Fprintf(c.Out, "\nMODO ASISTIDO ACTIVO. Ejecución %s: cada paso que cambia la red pide confirmación.\n", run.RunId)
	return cli.Follow(c, cl, run.RunId, 0, nil)
}

func runs(c *cli.Env, args []string) error {
	var onlyActive bool
	fs, err := cli.Flags("ports runs", args, func(fs *flag.FlagSet) { fs.BoolVar(&onlyActive, "activas", false, "solo las que siguen vivas") })
	if err != nil || fs.NArg() != 0 {
		return errors.New("uso: mctl ports runs [--activas]")
	}
	r, err := v1.NewAssistServiceClient(c.Conn).ListRuns(context.Background(), &v1.ListRunsRequest{ActiveOnly: onlyActive})
	if err != nil {
		return err
	}
	if len(r.Runs) == 0 {
		fmt.Fprintln(c.Out, "No hay ejecuciones.")
	}
	for _, st := range r.Runs {
		fmt.Fprintln(c.Out, cli.StateLine(st))
	}
	return nil
}

// resume retoma una ejecución viva: muestra dónde quedó, pide la decisión pendiente y sigue el resto.
func resume(c *cli.Env, args []string) error {
	if len(args) != 1 {
		return errors.New("uso: mctl ports resume EJECUCION")
	}
	cl := v1.NewAssistServiceClient(c.Conn)
	g, err := cl.GetAssistRun(context.Background(), &v1.GetAssistRunRequest{RunId: args[0]})
	if err != nil {
		return err
	}
	st := g.Run
	if !st.Active {
		return fmt.Errorf("la ejecución %s ya terminó: %s", st.RunId, cli.StateLine(st))
	}
	fmt.Fprintf(c.Out, "MODO ASISTIDO ACTIVO. Retomando la ejecución %s.\n%s\n", st.RunId, cli.StateLine(st))
	return cli.Follow(c, cl, st.RunId, st.EventCount, st)
}

// Area registra ports set.
func Area() cli.Area {
	return cli.Area{Usage: help, Commands: []cli.Command{{Name: "ports set", Run: set}, {Name: "ports runs", Run: runs}, {Name: "ports resume", Run: resume}}}
}
