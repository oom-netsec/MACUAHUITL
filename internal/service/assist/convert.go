package assist

import (
	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/assist"
)

func planToProto(p assist.Plan) *v1.AssistPlan {
	out := &v1.AssistPlan{Function: p.Function, WriteMemory: p.WriteMemory}
	for _, d := range p.Devices {
		dp := &v1.AssistDevicePlan{Device: d.Device, Pre: d.Pre, Apply: d.Apply, Rollback: d.Rollback, Post: d.Post, Notes: d.Notes}
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

func snapshot(rr *runRec) *v1.AssistRunState {
	sn := rr.run.Snapshot()
	return &v1.AssistRunState{RunId: rr.run.ID(), State: string(sn.State), Pending: stepToProto(sn.Pending), FailReason: sn.Reason,
		Changed: sn.Changed, Active: !sn.Finished, Waiting: sn.Waiting, CanRollback: sn.CanRollback, Devices: sn.Devices,
		StartedUnix: rr.started.Unix(), EventCount: uint32(sn.Events)}
}

func eventToProto(e assist.Event) *v1.AssistEvent {
	return &v1.AssistEvent{Seq: uint32(e.Seq), Kind: string(e.Kind), State: string(e.State), Step: stepToProto(e.Step), Device: e.Device, Text: e.Text, Changed: e.Changed}
}
