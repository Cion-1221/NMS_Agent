package scheduler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Cion-1221/NMS_Agent/internal/config"
	"github.com/Cion-1221/NMS_Agent/internal/probe"
	"github.com/Cion-1221/NMS_Agent/internal/reporter"
	"github.com/Cion-1221/NMS_Agent/internal/updater"
)

func TestTaskChangedAndSNMPParamsChanged(t *testing.T) {
	base := probe.Task{
		TaskID:          1,
		Type:            "httpcheck",
		IntervalSeconds: 60,
		Targets:         []string{"https://example.com"},
		AddressFamily:   "both",
	}
	if taskChanged(base, base) {
		t.Fatal("identical task reported changed")
	}

	diffFam := base
	diffFam.AddressFamily = "v4"
	if !taskChanged(base, diffFam) {
		t.Fatal("expected AddressFamily change to trigger restart")
	}

	s1 := &probe.SNMPParams{DeviceID: 10, Version: "2c", Community: "pub", ExtraOIDs: []string{"1.3.6.1.2.1.1.1.0"}}
	s2 := &probe.SNMPParams{DeviceID: 10, Version: "2c", Community: "priv", ExtraOIDs: []string{"1.3.6.1.2.1.1.1.0"}}
	if !snmpParamsChanged(s1, s2) {
		t.Fatal("expected SNMP community change to trigger restart")
	}
}

func TestSchedulerReconcileUpdateAndLifecycle(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(taskResponse{
			AgentID:    "AGT-1",
			SourceIPv4: "192.0.2.10",
			Tasks:      nil,
			Update: &updater.Update{
				Version:  "1.2.0",
				BinaryID: 7,
				SHA256:   "deadbeef",
				FileSize: 1024,
			},
		})
	}))
	defer srv.Close()

	cfg := config.ServerConfig{
		TaskPollInterval: time.Hour,
		FlushInterval:    time.Hour,
		BatchSize:        100,
		RequestTimeout:   5 * time.Second,
	}
	rep := reporter.New(srv.Client(), srv.URL, cfg)
	sched := New(srv.Client(), srv.URL, rep, cfg, 5)

	runners := make(map[int]*taskRunner)
	sched.reconcile(context.Background(), runners)

	select {
	case upd := <-sched.UpdateCh():
		if upd.Version != "1.2.0" || upd.BinaryID != 7 {
			t.Fatalf("unexpected update payload: %+v", upd)
		}
	default:
		t.Fatal("expected update notification on UpdateCh")
	}
}
