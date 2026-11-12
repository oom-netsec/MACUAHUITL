package assist

import (
	"context"
	"errors"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/assist"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

func planToProto(loc string, p assist.Plan) *v1.AssistPlan {
	out := &v1.AssistPlan{Function: p.Function, WriteMemory: p.WriteMemory}
	for _, d := range p.Devices {
		dp := &v1.AssistDevicePlan{Device: d.Device, Pre: d.Pre, Apply: d.Apply, Rollback: d.Rollback, Post: d.Post, Notes: notesIn(loc, d)}
		for _, n := range d.NoteItems {
			dp.NotesStructured = append(dp.NotesStructured, &v1.AssistNote{Key: n.Key, Args: n.Args})
		}
		for _, e := range d.Expect {
			dp.Expect = append(dp.Expect, &v1.AssistExpect{Command: e.Command, Line: e.Line, Present: e.Present, Prefix: e.Prefix, Column: e.Column})
		}
		out.Devices = append(out.Devices, dp)
	}
	return out
}

func stepToProto(s *assist.Step) *v1.AssistStep {
	if s == nil {
		return nil
	}
	return &v1.AssistStep{Id: s.ID, Kind: string(s.Kind), Device: s.Device, Lines: s.Lines}
}

func snapshot(loc string, rr *runRec) *v1.AssistRunState {
	sn := rr.run.Snapshot()
	return &v1.AssistRunState{RunId: rr.run.ID(), State: string(sn.State), Pending: stepToProto(sn.Pending), FailReason: reasonIn(loc, sn),
		Changed: sn.Changed, Active: !sn.Finished, Waiting: sn.Waiting, CanRollback: sn.CanRollback, Devices: sn.Devices,
		StartedUnix: rr.started.Unix(), EventCount: uint32(sn.Events)}
}

func eventToProto(loc string, e assist.Event) *v1.AssistEvent {
	return &v1.AssistEvent{Seq: uint32(e.Seq), Kind: string(e.Kind), State: string(e.State), Step: stepToProto(e.Step), Device: e.Device, Text: textIn(loc, e), Changed: e.Changed}
}

// notesIn son los avisos del plan en el idioma pedido (es es el texto de siempre).
func notesIn(loc string, d assist.DevicePlan) []string {
	if loc != i18n.En || len(d.NoteItems) != len(d.Notes) {
		return d.Notes
	}
	out := make([]string, len(d.NoteItems))
	for i, n := range d.NoteItems {
		out[i] = n.In(loc)
	}
	return out
}

// reasonIn es el motivo de la parada en el idioma pedido; solo el inglés tiene otra versión.
func reasonIn(loc string, sn assist.Snapshot) string {
	if loc == i18n.En && sn.ReasonEN != "" {
		return sn.ReasonEN
	}
	return sn.Reason
}

func textIn(loc string, e assist.Event) string {
	if loc == i18n.En && e.TextEN != "" {
		return e.TextEN
	}
	return e.Text
}

// coded es el texto de err en el idioma del contexto (el de siempre si no trae código).
func coded(ctx context.Context, err error) string {
	var c i18n.Coded
	if loc := i18n.Locale(ctx); loc != i18n.Es && errors.As(err, &c) {
		return c.Localize(loc)
	}
	return err.Error()
}
