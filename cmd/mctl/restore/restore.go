// Package restore es el área de mctl para restaurar un respaldo de configuración con el modo de cambio asistido (ADR 0007). Sin --asistido
// solo muestra el plan (con su reversa y lo que no se restaura); nada se cambia hasta que el ingeniero confirma cada paso.
package restore

import (
	"context"
	"errors"
	"flag"
	"fmt"

	"github.com/oom-netsec/MACUAHUITL/cmd/mctl/cli"
	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
)

const help = `  restore diff EQUIPO[:PUERTO] RESPALDO --cred ID [--mgmt-if IF] [--max-lines N] [--parcial] [--write-memory] [--accept HUELLA]... [--asistido]
        (lleva el running-config del equipo al de un respaldo (ID de "backup list": equipo/AAAAMMDDTHHMMSSZ-running) cambiando solo las
         líneas que difieren, con su reversa. Lista cerrada: hostname, logging, ntp server, snmp-server location|contact, ip domain-name,
         ip name-server, clock, service timestamps, spanning-tree portfast default, errdisable recovery, nombre de VLAN y, en puertos físicos de acceso,
         description, VLAN de acceso y de voz, shutdown, portfast, bpduguard y storm-control. Todo lo demás (rutas, router, ACL, vrf, trunk,
         canales, SVI, line, aaa, usuarios, crypto, standby, autenticación, contraseñas) se lista para hacerlo a mano y rechaza el plan
         entero, salvo con --parcial. Solo respaldos sin enmascarar, completos (terminan en end), con ficha firmada por la bóveda y del
         mismo equipo (número de serie). Nunca toca la interfaz por la que te conectas ni las que llevan su VLAN: se identifica con
         show users, show tcp brief y la salida hacia ti (show ip cef); si no es segura, indícala con --mgmt-if. Tope de líneas: 200 por omisión.
         Sin --asistido solo muestra el plan; con --asistido pide confirmación en cada paso: s/N, r = revertir)`

func diff(c *cli.Env, args []string) error {
	var credID, mgmt string
	var maxLines uint
	var partial, assisted, writeMe bool
	var accept cli.List
	fs, err := cli.Flags("restore diff", args, func(fs *flag.FlagSet) {
		fs.StringVar(&credID, "cred", "", "ID de la credencial")
		fs.StringVar(&mgmt, "mgmt-if", "", "interfaz por la que estás conectado (no se toca)")
		fs.UintVar(&maxLines, "max-lines", 0, "tope de líneas de cambio (0 = 200; máximo 1000)")
		fs.BoolVar(&partial, "parcial", false, "aplicar solo lo permitido y listar el resto")
		fs.BoolVar(&assisted, "asistido", false, "aplicar el cambio con confirmación por paso")
		fs.BoolVar(&writeMe, "write-memory", false, "agrega el paso final write memory")
		fs.Var(&accept, "accept", "huella SHA256 confirmada (repetible)")
	})
	if err != nil || fs.NArg() != 2 || credID == "" {
		return errors.New("uso: mctl restore diff EQUIPO[:PUERTO] RESPALDO --cred ID [--mgmt-if IF] [--max-lines N] [--parcial] [--asistido]")
	}
	if maxLines > 1000 {
		return cli.Err("mctl.restore.max_lines")
	}
	addr, port, err := cli.SplitHost(fs.Arg(0))
	if err != nil {
		return err
	}
	cl := v1.NewAssistServiceClient(c.Conn)
	res, err := cl.PlanRestore(context.Background(), &v1.PlanRestoreRequest{Target: &v1.AssistTarget{Name: addr, Address: addr, Port: port, CredentialId: credID},
		BackupId: fs.Arg(1), ManagementInterface: mgmt, MaxLines: uint32(maxLines), AllowPartial: partial, WriteMemory: writeMe, AcceptedHostKeyFingerprints: accept})
	if err != nil {
		return err
	}
	if res.PlanId == "" {
		fmt.Fprintln(c.Out, cli.T("mctl.restore.rejected", "reason", res.Reason))
		printRefused(c, res.Refused, cli.T("mctl.restore.refused"))
		return cli.Err("mctl.restore.rejected_err")
	}
	cli.PrintPlan(c.Out, res.Plan)
	printRefused(c, res.Refused, "\n"+cli.T("mctl.restore.refused_partial"))
	if !assisted {
		fmt.Fprintln(c.Out, "\n"+cli.T("mctl.restore.plan_only"))
		return nil
	}
	run, err := cl.StartRun(context.Background(), &v1.StartRunRequest{PlanId: res.PlanId, Assisted: true})
	if err != nil {
		return err
	}
	fmt.Fprintln(c.Out, "\n"+cli.T("mctl.restore.assist_active", "run", run.RunId))
	return cli.Follow(c, cl, run.RunId, 0, nil)
}

func printRefused(c *cli.Env, rs []*v1.RestoreRefusal, title string) {
	if len(rs) == 0 {
		return
	}
	fmt.Fprintln(c.Out, title)
	for _, r := range rs {
		where := ""
		if r.Path != "" {
			where = r.Path + " > "
		}
		fmt.Fprintf(c.Out, "  %s%s  (%s)\n", where, r.Line, r.Why)
	}
}

// Area registra restore diff.
func Area() cli.Area {
	return cli.Area{Usage: help, Commands: []cli.Command{{Name: "restore diff", Run: diff}}}
}
