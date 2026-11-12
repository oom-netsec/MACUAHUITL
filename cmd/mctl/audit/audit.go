package audit

import (
	"context"
	"fmt"
	"io"

	"github.com/oom-netsec/MACUAHUITL/cmd/mctl/cli"
	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
)

func auditVerify(c *cli.Env, args []string) error {
	if _, err := cli.Flags("audit verify", args, nil); err != nil {
		return err
	}
	r, err := v1.NewAuditServiceClient(c.Conn).Verify(context.Background(), &v1.VerifyRequest{})
	if err != nil {
		return err
	}
	if !r.Intact {
		return fmt.Errorf("la cadena de auditoría está rota en el registro %d", r.FirstBrokenSeq)
	}
	fmt.Fprintf(c.Out, "cadena íntegra; cabeza %s\n", r.HeadHash)
	return nil
}

func auditExport(c *cli.Env, args []string) error {
	if _, err := cli.Flags("audit export", args, nil); err != nil {
		return err
	}
	st, err := v1.NewAuditServiceClient(c.Conn).Export(context.Background(), &v1.ExportRequest{})
	if err != nil {
		return err
	}
	for {
		r, err := st.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		fmt.Fprintln(c.Out, r.JsonLine)
	}
}

// help son las líneas de este área en mctl --help.
const help = `  audit verify | export`

// Area registra los comandos de audit.
func Area() cli.Area {
	return cli.Area{Usage: help, Commands: []cli.Command{
		{Name: "audit verify", Run: auditVerify},
		{Name: "audit export", Run: auditExport},
	}}
}
