package bridge

import (
	"context"
	"fmt"

	"google.golang.org/protobuf/encoding/protojson"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
)

// ---- Ventana de cambio (PRE/POST, upgrade, cumplimiento) ----

// ReportDTO lleva el reporte como JSON (para el semáforo) y como texto.
type ReportDTO struct {
	Json string `json:"json"`
	Text string `json:"text"`
}

func toReport(r *v1.ToolReport) ReportDTO { return ReportDTO{Json: r.GetJson(), Text: r.GetText()} }

// ChangeCreate recibe el JobSpec como JSON, igual que CreateJob.
func (b *Bridge) ChangeCreate(specJSON string) (string, error) {
	var spec v1.JobSpec
	if err := protojson.Unmarshal([]byte(specJSON), &spec); err != nil {
		return "", wrapErr(err)
	}
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (string, error) {
		r, err := v1.NewChangeServiceClient(c).CreateChange(ctx, &v1.CreateChangeRequest{Spec: &spec})
		return r.GetChangeId(), err
	})
}

type CaptureDTO struct {
	JobID  string `json:"jobId"`
	Armed  bool   `json:"armed"`
	Detail string `json:"detail"`
}

var changePhases = map[string]v1.ChangePhase{"pre": v1.ChangePhase_CHANGE_PHASE_PRE, "post": v1.ChangePhase_CHANGE_PHASE_POST}

func (b *Bridge) ChangeCapture(changeID, phase string, accept, exclude []string) (CaptureDTO, error) {
	ph, ok := changePhases[phase]
	if !ok {
		return CaptureDTO{}, wrapErr(fmt.Errorf("fase %q desconocida", phase))
	}
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (CaptureDTO, error) {
		r, err := v1.NewChangeServiceClient(c).CaptureChange(ctx, &v1.CaptureChangeRequest{ChangeId: changeID, Phase: ph, AcceptedHostKeyFingerprints: accept, ExcludedDeviceIds: exclude})
		if err != nil {
			return CaptureDTO{}, err
		}
		return CaptureDTO{JobID: r.JobId, Armed: r.Armed, Detail: r.Detail}, nil
	})
}

type ChangeDTO struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	PreJobID  string `json:"preJobId"`
	PreState  string `json:"preState"`
	PostJobID string `json:"postJobId"`
	PostState string `json:"postState"`
}

func (b *Bridge) ListChanges() ([]ChangeDTO, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) ([]ChangeDTO, error) {
		r, err := v1.NewChangeServiceClient(c).ListChanges(ctx, &v1.ListChangesRequest{})
		if err != nil {
			return nil, err
		}
		out := []ChangeDTO{}
		for _, x := range r.Changes {
			out = append(out, ChangeDTO{ID: x.ChangeId, Name: x.Name, PreJobID: x.PreJobId, PreState: x.PreState, PostJobID: x.PostJobId, PostState: x.PostState})
		}
		return out, nil
	})
}

func (b *Bridge) ChangeReport(changeID, preDir, postDir string) (ReportDTO, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (ReportDTO, error) {
		r, err := v1.NewChangeServiceClient(c).GetChangeReport(ctx, &v1.GetChangeReportRequest{ChangeId: changeID, PreDir: preDir, PostDir: postDir})
		return toReport(r.GetReport()), err
	})
}

type UpgradeDTO struct {
	Outputs string `json:"outputs"`
	Image   string `json:"image"`
	Size    int64  `json:"size"`
	MD5     string `json:"md5"`
	Verify  string `json:"verify"`
}

func (b *Bridge) UpgradeCheck(u UpgradeDTO) (ReportDTO, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (ReportDTO, error) {
		r, err := v1.NewChangeServiceClient(c).CheckUpgrade(ctx, &v1.CheckUpgradeRequest{Outputs: u.Outputs, ImageFile: u.Image, ImageSize: u.Size, ImageMd5: u.MD5, VerifyOutput: u.Verify})
		return toReport(r.GetReport()), err
	})
}

func (b *Bridge) ComplianceCheck(config, template string) (ReportDTO, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (ReportDTO, error) {
		r, err := v1.NewChangeServiceClient(c).CheckCompliance(ctx, &v1.CheckComplianceRequest{Config: config, Template: template})
		return toReport(r.GetReport()), err
	})
}
