package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"runtime"
	"sync/atomic"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	protoICMP    = 1
	protoICMPv6  = 58
	traceMaxHops = 30
	traceHopWait = 3 * time.Second
)

type traceHop struct {
	TTL     int     `json:"ttl"`
	IP      string  `json:"ip,omitempty"`
	RTTMs   float64 `json:"rtt_ms,omitempty"`
	Timeout bool    `json:"timeout,omitempty"`
}

type traceDetail struct {
	Hops    []traceHop `json:"hops"`
	Reached bool       `json:"reached"`
}

type traceParams struct {
	isV4     bool
	echoType icmp.Type
	proto    int
}

// traceID hands out a distinct ICMP echo identifier per traceroute run so
// concurrent traceroute tasks in this process cannot claim each other's replies.
var traceID atomic.Uint32

func runTraceroute(ctx context.Context, task Task, sourceIPv4, sourceIPv6 string, lim Limiter) []Result {
	results := make([]Result, 0, len(task.Targets))
	// Traceroute runs targets serially: concurrent raw-socket probes on the same
	// host race for ICMP replies and produce unreliable hop attribution.
	for _, target := range task.Targets {
		for _, fp := range famProbesFor(task.AddressFamily, target) {
			if !lim.Acquire(ctx) {
				return results
			}
			r := stamp(doTraceroute(ctx, task.TaskID, task.Type, target, fp, sourceIPv4, sourceIPv6))
			lim.Release()
			results = append(results, r)
		}
	}
	return results
}

func doTraceroute(ctx context.Context, taskID int, taskType, target string, fp famProbe, sourceIPv4, sourceIPv6 string) Result {
	r := Result{TaskID: taskID, Type: taskType, Target: target + fp.label}

	if runtime.GOOS == "windows" {
		r.Detail = "traceroute requires raw ICMP sockets; on Windows run the agent as Administrator or use tcpping instead"
		return r
	}

	// Family-restricted resolution for domain targets (literal IPs pass through).
	ipStr, err := resolveTargetIP(ctx, target, fp.family)
	if err != nil {
		r.Detail = fmt.Sprintf("resolve: %v", err)
		return r
	}
	dstIP := net.ParseIP(ipStr)

	isV4 := dstIP.To4() != nil
	var params traceParams
	var listenNet, listenAddr string

	// Bind to the source address matching the target's address family.
	if isV4 {
		params = traceParams{isV4: true, echoType: ipv4.ICMPTypeEcho, proto: protoICMP}
		listenNet = "ip4:icmp"
		listenAddr = "0.0.0.0"
		if sourceIPv4 != "" {
			listenAddr = sourceIPv4
		}
	} else {
		params = traceParams{isV4: false, echoType: ipv6.ICMPTypeEchoRequest, proto: protoICMPv6}
		listenNet = "ip6:ipv6-icmp"
		listenAddr = "::"
		if sourceIPv6 != "" {
			listenAddr = sourceIPv6
		}
	}

	conn, err := icmp.ListenPacket(listenNet, listenAddr)
	if err != nil {
		r.Detail = fmt.Sprintf("raw socket (need root/CAP_NET_RAW): %v", err)
		return r
	}
	defer conn.Close()

	id := int(traceID.Add(1) & 0xffff)
	dstAddr := &net.IPAddr{IP: dstIP}
	var detail traceDetail

	for ttl := 1; ttl <= traceMaxHops; ttl++ {
		if ctx.Err() != nil {
			break
		}

		ip, rttMs, timedOut := probeHop(conn, dstAddr, params, ttl, id)
		hop := traceHop{TTL: ttl, IP: ip, RTTMs: rttMs, Timeout: timedOut}
		detail.Hops = append(detail.Hops, hop)

		if !timedOut && ip == dstIP.String() {
			detail.Reached = true
			v := rttMs
			r.Success = true
			r.LatencyMs = &v
			break
		}
	}

	if b, err := json.Marshal(detail); err == nil {
		r.Detail = string(b)
	}
	return r
}

func probeHop(conn *icmp.PacketConn, dst net.Addr, params traceParams, ttl, id int) (ip string, rttMs float64, timeout bool) {
	// Set TTL / Hop Limit before sending so the next packet uses this value.
	if params.isV4 {
		_ = conn.IPv4PacketConn().SetTTL(ttl)
	} else {
		_ = conn.IPv6PacketConn().SetHopLimit(ttl)
	}

	msg := icmp.Message{
		Type: params.echoType, Code: 0,
		Body: &icmp.Echo{ID: id, Seq: ttl, Data: []byte("nms-trace")},
	}
	wb, err := msg.Marshal(nil)
	if err != nil {
		return "", 0, true
	}

	sendAt := time.Now()
	if _, err := conn.WriteTo(wb, dst); err != nil {
		return "", 0, true
	}

	_ = conn.SetReadDeadline(time.Now().Add(traceHopWait))
	buf := make([]byte, 1500)

	for {
		n, peer, err := conn.ReadFrom(buf)
		if err != nil {
			return "", 0, true // deadline exceeded → hop timed out
		}
		rm, err := icmp.ParseMessage(params.proto, buf[:n])
		if err != nil {
			continue
		}
		rtt := float64(time.Since(sendAt)) / float64(time.Millisecond)

		switch body := rm.Body.(type) {
		case *icmp.TimeExceeded:
			// Only accept expirations of OUR probe: the payload embeds the
			// original IP header + first 8 bytes of the echo we sent, which
			// carry its ID and sequence number.
			if matchesEcho(body.Data, params.isV4, id, ttl) {
				return peer.String(), rtt, false
			}
		case *icmp.Echo:
			if body.ID == id && body.Seq == ttl {
				return peer.String(), rtt, false
			}
		}
	}
}

// matchesEcho reports whether a TimeExceeded payload embeds the echo request
// identified by id/seq. The payload starts with the original IP header
// (variable-length IHL for IPv4, fixed 40 bytes for IPv6 — our probes carry
// no extension headers) followed by at least 8 bytes of the original ICMP
// message, whose ID sits at offset 4-5 and Seq at 6-7 (big-endian).
func matchesEcho(data []byte, isV4 bool, id, seq int) bool {
	var inner []byte
	if isV4 {
		if len(data) < 1 {
			return false
		}
		ihl := int(data[0]&0x0f) * 4
		if ihl < 20 || len(data) < ihl+8 {
			return false
		}
		inner = data[ihl:]
	} else {
		if len(data) < 40+8 {
			return false
		}
		inner = data[40:]
	}
	embID := int(inner[4])<<8 | int(inner[5])
	embSeq := int(inner[6])<<8 | int(inner[7])
	return embID == id && embSeq == seq
}
