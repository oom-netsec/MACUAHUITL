package bridge

import (
	"context"
	"encoding/json"
	"io"

	"google.golang.org/protobuf/encoding/protojson"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
)

// ---- Modo de cambio asistido (ADR 0007) ----
// El puente no decide nada: reenvía al núcleo, que valida el plan y exige assisted=true.

// AssistPlanPorts recibe PlanPortsRequest como JSON y devuelve PlanPortsResponse como JSON (solo lee).
func (b *Bridge) AssistPlanPorts(reqJSON string) (string, error) {
	var req v1.PlanPortsRequest
	if err := protojson.Unmarshal([]byte(reqJSON), &req); err != nil {
		return "", err
	}
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (string, error) {
		r, err := v1.NewAssistServiceClient(c).PlanPorts(ctx, &req)
		if err != nil {
			return "", err
		}
		raw, err := protojson.Marshal(r)
		return string(raw), err
	})
}

// AssistPlanSnippet recibe PlanSnippetRequest como JSON (vlan, trunk, svi o template del catálogo) y devuelve PlanSnippetResponse como JSON (solo lee).
func (b *Bridge) AssistPlanSnippet(reqJSON string) (string, error) {
	var req v1.PlanSnippetRequest
	if err := protojson.Unmarshal([]byte(reqJSON), &req); err != nil {
		return "", err
	}
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (string, error) {
		r, err := v1.NewAssistServiceClient(c).PlanSnippet(ctx, &req)
		if err != nil {
			return "", err
		}
		raw, err := protojson.Marshal(r)
		return string(raw), err
	})
}

// AssistListSnippetTemplates devuelve ListSnippetTemplatesResponse como JSON: el catálogo de plantillas con sus campos tipados (platform vacío = todas).
func (b *Bridge) AssistListSnippetTemplates(platform string) (string, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (string, error) {
		r, err := v1.NewAssistServiceClient(c).ListSnippetTemplates(ctx, &v1.ListSnippetTemplatesRequest{Platform: platform})
		if err != nil {
			return "", err
		}
		raw, err := protojson.Marshal(r)
		return string(raw), err
	})
}

// AssistPlanCredRotate recibe PlanCredRotateRequest como JSON y devuelve la respuesta como JSON. El secreto nuevo (si el usuario lo da)
// viaja solo en la petición al núcleo: el puente no lo guarda, no lo registra y la respuesta no lo trae.
func (b *Bridge) AssistPlanCredRotate(reqJSON string) (string, error) {
	var req v1.PlanCredRotateRequest
	if err := protojson.Unmarshal([]byte(reqJSON), &req); err != nil {
		return "", err
	}
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (string, error) {
		r, err := v1.NewAssistServiceClient(c).PlanCredRotate(ctx, &req)
		if err != nil {
			return "", err
		}
		raw, err := protojson.Marshal(r)
		return string(raw), err
	})
}

// AssistPlanRestore recibe PlanRestoreRequest como JSON (respaldo, interfaz de gestión, tope, parcial) y devuelve PlanRestoreResponse como
// JSON con el plan o, si se rechazó, la lista de lo que no se restaura (solo lee).
func (b *Bridge) AssistPlanRestore(reqJSON string) (string, error) {
	var req v1.PlanRestoreRequest
	if err := protojson.Unmarshal([]byte(reqJSON), &req); err != nil {
		return "", err
	}
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (string, error) {
		r, err := v1.NewAssistServiceClient(c).PlanRestore(ctx, &req)
		if err != nil {
			return "", err
		}
		raw, err := protojson.Marshal(r)
		return string(raw), err
	})
}

// AssistStart inicia la ejecución y devuelve su id, sin abrir el stream: la vista guarda el id y luego
// llama a AssistWatch, así ningún evento (un fallo rápido, por ejemplo) llega antes de que sepa de quién es.
// assisted viene de la casilla de esa ejecución, nunca de un ajuste.
func (b *Bridge) AssistStart(planID string, assisted bool) (string, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (string, error) {
		r, err := v1.NewAssistServiceClient(c).StartRun(ctx, &v1.StartRunRequest{PlanId: planID, Assisted: assisted})
		return r.GetRunId(), err
	})
}

// AssistWatch reenvía los eventos de la ejecución, desde el primero, como assist:event {runId, event}; al
// cerrarse el stream emite assist:done {runId}. Sirve igual para una ejecución recién iniciada que para
// volver a una que quedó viva (ver AssistListRuns).
func (b *Bridge) AssistWatch(runID string) error {
	c, err := b.client()
	if err != nil {
		return err
	}
	st, err := v1.NewAssistServiceClient(c).WatchRun(b.callCtx(), &v1.WatchRunRequest{RunId: runID})
	if err != nil {
		return err
	}
	go func() {
		for {
			m, err := st.Recv()
			if err != nil {
				if err != io.EOF {
					b.emit("assist:done", map[string]any{"runId": runID, "error": err.Error()})
				} else {
					b.emit("assist:done", map[string]any{"runId": runID})
				}
				return
			}
			raw, _ := protojson.Marshal(m.Event)
			b.emit("assist:event", map[string]any{"runId": runID, "event": json.RawMessage(raw)})
		}
	}()
	return nil
}

// AssistListRuns devuelve ListRunsResponse como JSON con las ejecuciones que siguen vivas.
func (b *Bridge) AssistListRuns() (string, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (string, error) {
		r, err := v1.NewAssistServiceClient(c).ListRuns(ctx, &v1.ListRunsRequest{ActiveOnly: true})
		if err != nil {
			return "", err
		}
		raw, err := protojson.Marshal(r)
		return string(raw), err
	})
}

func (b *Bridge) AssistConfirm(runID, stepID string) error {
	_, err := call(b, func(ctx context.Context, c *ipc.ClientConn) (struct{}, error) {
		_, err := v1.NewAssistServiceClient(c).Confirm(ctx, &v1.ConfirmRequest{RunId: runID, StepId: stepID})
		return struct{}{}, err
	})
	return err
}

func (b *Bridge) AssistAbort(runID string) error {
	_, err := call(b, func(ctx context.Context, c *ipc.ClientConn) (struct{}, error) {
		_, err := v1.NewAssistServiceClient(c).Abort(ctx, &v1.AbortRequest{RunId: runID})
		return struct{}{}, err
	})
	return err
}

func (b *Bridge) AssistRollback(runID string) error {
	_, err := call(b, func(ctx context.Context, c *ipc.ClientConn) (struct{}, error) {
		_, err := v1.NewAssistServiceClient(c).Rollback(ctx, &v1.RollbackRequest{RunId: runID})
		return struct{}{}, err
	})
	return err
}
