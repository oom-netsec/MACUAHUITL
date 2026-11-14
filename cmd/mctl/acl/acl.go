package acl

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/oom-netsec/MACUAHUITL/cmd/mctl/cli"
	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
)

func importACL(c *cli.Env, vendor, file string) (*v1.Acl, error) {
	if vendor == "" || file == "" {
		return nil, cli.Err("mctl.acl.missing_flags")
	}
	b, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	r, err := v1.NewAclServiceClient(c.Conn).Import(context.Background(), &v1.ImportRequest{Vendor: vendor, Text: string(b)})
	if err != nil {
		return nil, err
	}
	return r.Acl, nil
}

func aclConvert(c *cli.Env, args []string) error {
	var from, to, file string
	if _, err := cli.Flags("acl convert", args, func(fs *flag.FlagSet) {
		fs.StringVar(&from, "from", "", "fabricante de origen")
		fs.StringVar(&to, "to", "", "fabricante de destino")
		fs.StringVar(&file, "f", "", "archivo con la ACL")
	}); err != nil {
		return err
	}
	a, err := importACL(c, from, file)
	if err != nil {
		return err
	}
	r, err := v1.NewAclServiceClient(c.Conn).Generate(context.Background(), &v1.GenerateRequest{Acl: a, Vendor: to})
	if err != nil {
		return err
	}
	fmt.Fprint(c.Out, r.Script)
	return nil
}

func aclAnalyze(c *cli.Env, args []string) error {
	var vendor, file string
	if _, err := cli.Flags("acl analyze", args, func(fs *flag.FlagSet) {
		fs.StringVar(&vendor, "vendor", "", "fabricante")
		fs.StringVar(&file, "f", "", "archivo con la ACL")
	}); err != nil {
		return err
	}
	a, err := importACL(c, vendor, file)
	if err != nil {
		return err
	}
	r, err := v1.NewAclServiceClient(c.Conn).Analyze(context.Background(), &v1.AnalyzeRequest{Acl: a})
	if err != nil {
		return err
	}
	kinds := map[string]string{"shadowed": cli.T("mctl.acl.shadowed"), "redundant": cli.T("mctl.acl.redundant"), "impossible": cli.T("mctl.acl.impossible")}
	for _, f := range r.Findings {
		fmt.Fprintln(c.Out, cli.T("mctl.acl.finding", "n", f.RuleIndex+1, "kind", kinds[f.Kind], "detail", f.Detail))
	}
	if len(r.Findings) > 0 {
		return cli.Err("mctl.acl.findings", "n", len(r.Findings), "name", a.Name)
	}
	fmt.Fprintln(c.Out, cli.T("mctl.acl.clean", "name", a.Name, "n", len(a.Rules)))
	return nil
}

// help son las líneas de este área en mctl --help.
const help = `  acl   convert --from F --to F -f acl.txt | analyze --vendor F -f acl.txt   (F: ios-xe, nx-os, asa)`

// Area registra los comandos de acl.
func Area() cli.Area {
	return cli.Area{Usage: help, Commands: []cli.Command{
		{Name: "acl convert", Run: aclConvert},
		{Name: "acl analyze", Run: aclAnalyze},
	}}
}
