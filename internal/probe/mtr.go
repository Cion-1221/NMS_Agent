package probe

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"runtime"
)

type mtrHop struct {
	TTL        int     `json:"ttl"`
	Host       string  `json:"host,omitempty"`
	LossRate   float64 `json:"loss_rate"`
	AvgRttMs   float64 `json:"avg_rtt_ms"`
	BestRttMs  float64 `json:"best_rtt_ms"`
	WorstRttMs float64 `json:"worst_rtt_ms"`
	StdDevMs   float64 `json:"stddev_rtt_ms"`
}

// mtrJSONReport mirrors `mtr --report --json` output structure.
type mtrJSONReport struct {
	Report struct {
		Hubs []struct {
			Host  string  `json:"host"`
			Loss  float64 `json:"Loss%"`
			Avg   float64 `json:"Avg"`
			Best  float64 `json:"Best"`
			Wrst  float64 `json:"Wrst"`
			StDev float64 `json:"StDev"`
		} `json:"hubs"`
	} `json:"report"`
}

var mtrBinary string

func init() {
	mtrBinary, _ = exec.LookPath("mtr")
}

func runMTR(ctx context.Context, task Task, sourceIPv4, sourceIPv6 string, lim Limiter) []Result {
	return runJobs(ctx, task, lim, nil, func(ctx context.Context, target string, fp famProbe) Result {
		return doMTR(ctx, task.TaskID, task.Type, target, fp, sourceIPv4, sourceIPv6)
	})
}

func doMTR(ctx context.Context, taskID int, taskType, target string, fp famProbe, sourceIPv4, sourceIPv6 string) Result {
	r := Result{TaskID: taskID, Type: taskType, Target: target + fp.label}

	if runtime.GOOS == "windows" {
		r.Detail = "mtr is not available on Windows; use traceroute (requires admin) or tcpping instead"
		return r
	}

	if mtrBinary == "" {
		r.Detail = "mtr binary not found in PATH (install mtr or mtr-tiny)"
		return r
	}

	args := []string{
		"--report", "--json", "--no-dns",
		"--report-cycles", "10",
		"--max-ttl", "30",
	}
	// Force the resolution family for domain targets; mtr resolves internally.
	switch fp.family {
	case "ip4":
		args = append(args, "-4")
	case "ip6":
		args = append(args, "-6")
	}
	// mtr --address binds the probe socket; pick the source matching the target family.
	src := sourceIPForFamily(fp.family, sourceIPv4, sourceIPv6)
	if src == "" && fp.family == "" {
		src = pickSourceIP(target, sourceIPv4, sourceIPv6)
	}
	if src != "" {
		args = append(args, "--address", src)
	}
	args = append(args, target)

	cmd := exec.CommandContext(ctx, mtrBinary, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C")

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		r.Detail = fmt.Sprintf("mtr: %v (stderr: %s)", err, stderr.String())
		return r
	}

	var rep mtrJSONReport
	if err := json.Unmarshal(stdout.Bytes(), &rep); err != nil {
		r.Detail = fmt.Sprintf("parse mtr json: %v", err)
		return r
	}

	hops := make([]mtrHop, 0, len(rep.Report.Hubs))
	for i, h := range rep.Report.Hubs {
		hops = append(hops, mtrHop{
			TTL:        i + 1,
			Host:       h.Host,
			LossRate:   h.Loss,
			AvgRttMs:   h.Avg,
			BestRttMs:  h.Best,
			WorstRttMs: h.Wrst,
			StdDevMs:   h.StDev,
		})
	}

	b, _ := json.Marshal(hops)
	r.Success = true
	r.Detail = string(b)
	return r
}
