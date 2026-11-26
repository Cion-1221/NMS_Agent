package probe

import (
	"context"
	"encoding/binary"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gosnmp/gosnmp"
)

func TestFamProbesFor(t *testing.T) {
	if got := famProbesFor("both", "1.1.1.1"); len(got) != 1 || got[0].label != "" {
		t.Fatalf("literal IPv4 must not expand under 'both': %+v", got)
	}
	if got := famProbesFor("both", "2001:4860:4860::8888"); len(got) != 1 || got[0].label != "" {
		t.Fatalf("literal IPv6 must not expand under 'both': %+v", got)
	}
	got := famProbesFor("both", "example.com")
	if len(got) != 2 || got[0].label != " (v4)" || got[1].label != " (v6)" {
		t.Fatalf("unexpected domain 'both' expansion: %+v", got)
	}
}

func TestParseDNSTarget(t *testing.T) {
	cases := []struct {
		in      string
		domain  string
		srv     string
		wantErr bool
	}{
		{"example.com", "example.com", "", false},
		{"example.com@1.1.1.1", "example.com", "1.1.1.1:53", false},
		{"example.com@8.8.8.8:5353", "example.com", "8.8.8.8:5353", false},
		{"example.com@2001:4860:4860::8888", "example.com", "[2001:4860:4860::8888]:53", false},
		{"example.com@[2001:4860:4860::8888]:5353", "example.com", "[2001:4860:4860::8888]:5353", false},
		{"@1.1.1.1", "", "", true},
		{"example.com@", "", "", true},
		{"", "", "", true},
	}
	for _, tc := range cases {
		d, s, err := parseDNSTarget(tc.in)
		if (err != nil) != tc.wantErr {
			t.Errorf("parseDNSTarget(%q) err=%v, wantErr=%v", tc.in, err, tc.wantErr)
			continue
		}
		if d != tc.domain || s != tc.srv {
			t.Errorf("parseDNSTarget(%q) = (%q, %q), want (%q, %q)", tc.in, d, s, tc.domain, tc.srv)
		}
	}
}

// TestDNSCheckTCPFallbackOnTruncatedUDP starts a local UDP+TCP DNS server on an
// ephemeral port: UDP replies with TC=1 (truncated), forcing Go's PreferGo
// resolver to retry over TCP. Verifies both domain@server:port routing and TCP
// fallback in doDNSCheck.
func TestDNSCheckTCPFallbackOnTruncatedUDP(t *testing.T) {
	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcpLn.Close()
	addr := tcpLn.Addr().String()

	udpConn, err := net.ListenPacket("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer udpConn.Close()

	var tcpHits atomic.Int32

	// UDP responder: echo transaction ID + flags QR=1, RD=1, RA=1, TC=1 (0x8380) with 0 answers.
	go func() {
		buf := make([]byte, 512)
		for {
			n, peer, err := udpConn.ReadFrom(buf)
			if err != nil || n < 12 {
				return
			}
			resp := make([]byte, n)
			copy(resp, buf[:n])
			resp[2] = 0x83 // QR=1, Opcode=0, AA=0, TC=1, RD=1
			resp[3] = 0x80 // RA=1, RCODE=0
			// Zero ANCOUNT/NSCOUNT/ARCOUNT, keep QDCOUNT and question section intact.
			binary.BigEndian.PutUint16(resp[6:8], 0)
			binary.BigEndian.PutUint16(resp[8:10], 0)
			binary.BigEndian.PutUint16(resp[10:12], 0)
			// Trim any EDNS additional record beyond the question section.
			qEnd := 12
			for qEnd < n && resp[qEnd] != 0 {
				qEnd += int(resp[qEnd]) + 1
			}
			if qEnd+5 <= n {
				qEnd += 5
			}
			_, _ = udpConn.WriteTo(resp[:qEnd], peer)
		}
	}()

	// TCP responder: return a valid A record 203.0.113.42 for the queried name.
	go func() {
		for {
			conn, err := tcpLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				tcpHits.Add(1)
				var length uint16
				if err := binary.Read(c, binary.BigEndian, &length); err != nil || length < 12 {
					return
				}
				req := make([]byte, length)
				if _, err := c.Read(req); err != nil {
					return
				}
				qEnd := 12
				for qEnd < len(req) && req[qEnd] != 0 {
					qEnd += int(req[qEnd]) + 1
				}
				if qEnd+5 > len(req) {
					return
				}
				qEnd += 5

				resp := make([]byte, 0, qEnd+16)
				resp = append(resp, req[:qEnd]...)
				resp[2] = 0x81 // QR=1, RD=1 (no TC)
				resp[3] = 0x80 // RA=1, NOERROR
				binary.BigEndian.PutUint16(resp[6:8], 1)  // ANCOUNT = 1
				binary.BigEndian.PutUint16(resp[8:10], 0) // NSCOUNT = 0
				binary.BigEndian.PutUint16(resp[10:12], 0)
				// Answer RR: pointer to offset 12 (0xc00c), Type A (1), Class IN (1), TTL 60, RDLENGTH 4, 203.0.113.42
				ans := []byte{
					0xc0, 0x0c,
					0x00, 0x01,
					0x00, 0x01,
					0x00, 0x00, 0x00, 0x3c,
					0x00, 0x04,
					203, 0, 113, 42,
				}
				resp = append(resp, ans...)

				out := make([]byte, 2+len(resp))
				binary.BigEndian.PutUint16(out[0:2], uint16(len(resp)))
				copy(out[2:], resp)
				_, _ = c.Write(out)
			}(conn)
		}
	}()

	target := "example.com@" + addr
	res := doDNSCheck(context.Background(), 1, target, famProbe{family: "ip4"}, "", "")
	if !res.Success {
		t.Fatalf("doDNSCheck TCP fallback failed: detail=%q", res.Detail)
	}
	if tcpHits.Load() == 0 {
		t.Fatal("expected DNS TCP fallback connection after TC=1 UDP reply")
	}
	if !strings.Contains(res.Detail, "203.0.113.42") {
		t.Fatalf("unexpected resolved detail: %q", res.Detail)
	}
}

func TestMTRBlocksFlagInjection(t *testing.T) {
	for _, bad := range []string{"-v", "--address=1.2.3.4", "   -4", ""} {
		res := doMTR(context.Background(), 1, "mtr", bad, famProbe{}, "", "")
		if res.Success || !strings.Contains(res.Detail, "invalid mtr target") {
			t.Fatalf("target %q was not rejected as flag injection: %+v", bad, res)
		}
	}
}

func TestTCPPingAndHTTPCheckLocal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/fail" {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	lim := NewLimiter(4)
	tcpAddr := strings.TrimPrefix(srv.URL, "http://")
	tcpRes := Dispatch(context.Background(), Task{TaskID: 1, Type: "tcpping", Targets: []string{tcpAddr}}, "", "", lim)
	if len(tcpRes) != 1 || !tcpRes[0].Success {
		t.Fatalf("tcpping failed: %+v", tcpRes)
	}

	httpOK := Dispatch(context.Background(), Task{TaskID: 2, Type: "httpcheck", Targets: []string{srv.URL}}, "", "", lim)
	if len(httpOK) != 1 || !httpOK[0].Success {
		t.Fatalf("httpcheck 200 failed: %+v", httpOK)
	}

	httpFail := Dispatch(context.Background(), Task{TaskID: 3, Type: "httpcheck", Targets: []string{srv.URL + "/fail"}}, "", "", lim)
	if len(httpFail) != 1 || httpFail[0].Success || httpFail[0].Detail != "HTTP 503" {
		t.Fatalf("httpcheck 503 unexpected: %+v", httpFail)
	}
}

func TestMatchesEchoAndSNMPHelpers(t *testing.T) {
	// IPv4 header with IHL=6 (24 bytes) + 8 bytes ICMP Echo (ID=0x1234, Seq=7)
	pktV4 := make([]byte, 24+8)
	pktV4[0] = 0x46 // Version 4, IHL 6 (24 bytes)
	pktV4[24+4] = 0x12
	pktV4[24+5] = 0x34
	pktV4[24+6] = 0x00
	pktV4[24+7] = 0x07
	if !matchesEcho(pktV4, true, 0x1234, 7) {
		t.Fatal("matchesEcho IPv4 IHL=24 failed")
	}

	if got := classifySNMPError(errors.New("usmStatsNotInTimeWindows")); got != "snmp_error" {
		t.Fatalf("notInTimeWindow classified as %q, want snmp_error", got)
	}
	if got := classifySNMPError(errors.New("wrong digest in USM")); got != "auth_fail" {
		t.Fatalf("USM digest classified as %q, want auth_fail", got)
	}

	// Counter64 > 2^63 must stay positive in both Value and Numeric.
	huge := new(big.Int).SetUint64(uint64(1)<<63 + 12345)
	val := decodeOIDValue("1.3.6.1.2.1.31.1.1.1.6.1", gosnmp.SnmpPDU{
		Type:  gosnmp.Counter64,
		Value: uint64(1)<<63 + 12345,
	})
	if val.Value != huge.String() || val.Numeric == nil || *val.Numeric <= 0 {
		t.Fatalf("Counter64 decode overflowed: %+v", val)
	}
}
