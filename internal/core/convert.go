package core

import (
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/engine"
	"github.com/oom-netsec/MACUAHUITL/internal/patrol"
)

func specFromProto(p *v1.JobSpec) patrol.Spec {
	s := patrol.Spec{
		Name: p.GetName(), DefaultCredentialID: p.GetDefaultCredentialId(), PlaybookIDs: p.GetPlaybookIds(),
		CustomCommands: p.GetCustomCommands(), OutputDir: p.GetOutputDir(), DeleteLooseFiles: p.GetDeleteLooseFiles(),
		DisableMasking: p.GetDisableMasking(), AcceptChangedHostKeys: p.GetAcceptChangedHostKeys(), WindowHours: p.GetWindowHours(),
	}
	for _, t := range p.GetTargets() {
		s.Targets = append(s.Targets, patrol.Target{Address: t.GetAddress(), Port: uint16(t.GetPort()), DeviceID: t.GetDeviceId()})
	}
	for _, o := range p.GetOverrides() {
		s.Overrides = append(s.Overrides, patrol.Override{DeviceID: o.GetDeviceId(), CredentialID: o.GetCredentialId(), FallbackCredentialID: o.GetFallbackCredentialId()})
	}
	if p.GetSplit() == v1.SplitStrategy_SPLIT_STRATEGY_CONSOLIDATED {
		s.Split = patrol.SplitConsolidated
	}
	switch p.GetZip() {
	case v1.ZipPolicy_ZIP_POLICY_NONE:
		s.Zip = patrol.ZipNone
	case v1.ZipPolicy_ZIP_POLICY_PER_ROUND:
		s.Zip = patrol.ZipPerRound
	}
	if sc := p.GetSchedule(); sc != nil {
		s.Schedule = patrol.Schedule{IntervalSeconds: sc.GetIntervalSeconds(), Rounds: sc.GetRounds(), Cron: sc.GetCron()}
		if sc.GetUntil() != nil {
			s.Schedule.Until = sc.GetUntil().AsTime()
		}
	}
	return s
}

func engineSchedule(s patrol.Schedule) engine.Schedule {
	return engine.Schedule{Interval: time.Duration(s.IntervalSeconds) * time.Second, Rounds: int(s.Rounds), Until: s.Until, Cron: s.Cron}
}

var deviceStates = map[string]v1.DeviceState{
	"connecting": v1.DeviceState_DEVICE_STATE_CONNECTING, "running": v1.DeviceState_DEVICE_STATE_RUNNING,
	"completed": v1.DeviceState_DEVICE_STATE_COMPLETED, "failed": v1.DeviceState_DEVICE_STATE_FAILED,
	"skipped": v1.DeviceState_DEVICE_STATE_SKIPPED, "cancelled": v1.DeviceState_DEVICE_STATE_CANCELLED,
}

var loginSteps = map[string]v1.LoginTestStep{
	"tcp": v1.LoginTestStep_LOGIN_TEST_STEP_TCP, "host_key": v1.LoginTestStep_LOGIN_TEST_STEP_HOST_KEY,
	"auth": v1.LoginTestStep_LOGIN_TEST_STEP_AUTH, "privilege": v1.LoginTestStep_LOGIN_TEST_STEP_PRIVILEGE,
	"prompt": v1.LoginTestStep_LOGIN_TEST_STEP_PROMPT, "platform": v1.LoginTestStep_LOGIN_TEST_STEP_PLATFORM,
}

func eventToProto(e engine.Event) *v1.SubscribeResponse {
	r := &v1.SubscribeResponse{At: timestamppb.New(e.At), JobId: e.JobID}
	switch e.Kind {
	case engine.DeviceState:
		r.Event = &v1.SubscribeResponse_DeviceStateChanged{DeviceStateChanged: &v1.DeviceStateChanged{DeviceId: e.DeviceID, State: deviceStates[e.State], Detail: e.Detail}}
	case engine.Progress:
		r.Event = &v1.SubscribeResponse_CommandProgress{CommandProgress: &v1.CommandProgress{DeviceId: e.DeviceID, Command: e.Command, Index: uint32(e.Index), Total: uint32(e.Total), BytesReceived: uint64(e.Bytes)}}
	case engine.Heartbeat:
		r.Event = &v1.SubscribeResponse_Heartbeat{Heartbeat: &v1.Heartbeat{}}
	case engine.JobState:
		r.Event = &v1.SubscribeResponse_JobStateChanged{JobStateChanged: &v1.JobStateChanged{State: e.State}}
	case engine.Warning:
		r.Event = &v1.SubscribeResponse_Warning{Warning: &v1.Warning{Code: e.Detail, Message: e.State}}
	case engine.Phase:
		r.Event = &v1.SubscribeResponse_PhaseAdded{PhaseAdded: phaseToProto(phase{At: e.At, Kind: e.State, Round: e.Index, Detail: e.Detail})}
	}
	return r
}
