package reporter

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/Cion-1221/NMS_Agent/internal/config"
	"github.com/Cion-1221/NMS_Agent/internal/probe"
)

func TestPendingBatchChunkedFlushAndPartialBackoff(t *testing.T) {
	pb := &pendingBatch[int]{kind: "probe", max: 1000}
	for i := 1; i <= 250; i++ {
		pb.add(i)
	}

	var chunks []int
	calls := 0
	pb.flush(100, false, func(batch []int) bool {
		calls++
		if calls == 2 {
			return false // fail on 2nd chunk after 1st chunk of 100 succeeded
		}
		chunks = append(chunks, len(batch))
		return true
	})

	if len(chunks) != 1 || chunks[0] != 100 {
		t.Fatalf("expected 1st chunk of 100 uploaded before failure, got %v", chunks)
	}
	if len(pb.buf) != 150 || pb.buf[0] != 101 {
		t.Fatalf("expected remaining 150 items starting at 101, got len=%d first=%d", len(pb.buf), pb.buf[0])
	}
	if pb.retryDelay != 5*time.Second {
		t.Fatalf("expected 5s initial backoff, got %v", pb.retryDelay)
	}

	// Force drain remaining 150 items in chunks [100, 50].
	pb.flush(100, true, func(batch []int) bool {
		chunks = append(chunks, len(batch))
		return true
	})
	if len(pb.buf) != 0 || pb.retryDelay != 0 {
		t.Fatalf("expected empty buffer after force drain, got len=%d delay=%v", len(pb.buf), pb.retryDelay)
	}
	if len(chunks) != 3 || chunks[1] != 100 || chunks[2] != 50 {
		t.Fatalf("expected chunk sizes [100, 100, 50], got %v", chunks)
	}
}

func TestPendingBatchEvictsOldestAtMax(t *testing.T) {
	pb := &pendingBatch[string]{kind: "probe", max: 3}
	for _, s := range []string{"a", "b", "c", "d", "e"} {
		pb.add(s)
	}
	if len(pb.buf) != 3 || pb.buf[0] != "c" || pb.buf[2] != "e" {
		t.Fatalf("unexpected buffer after eviction: %v", pb.buf)
	}
}

func TestReporterShutdownDrain(t *testing.T) {
	var mu sync.Mutex
	var received []probe.Result

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var p reportPayload
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			t.Errorf("decode: %v", err)
		}
		mu.Lock()
		received = append(received, p.Results...)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	rep := New(srv.Client(), srv.URL, config.ServerConfig{
		BatchSize:      2,
		FlushInterval:  time.Hour,
		RequestTimeout: 5 * time.Second,
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		rep.Run(ctx)
		close(done)
	}()

	for i := 0; i < 5; i++ {
		rep.Enqueue(probe.Result{TaskID: i + 1, Type: "ping", Target: "1.1.1.1", Success: true})
	}
	cancel()
	<-done

	mu.Lock()
	defer mu.Unlock()
	if len(received) != 5 {
		t.Fatalf("expected all 5 results flushed on shutdown, got %d", len(received))
	}
}
