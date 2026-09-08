package main

import "testing"

// The server's /my-ip endpoint answers with JSON; a bare-IP body must keep
// working as well. This contract silently broke once (the agent parsed the
// JSON as an IP string and discovery failed on every node), so pin it down.
func TestParseMyIPBody(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{"json ipv4", `{"ip":"203.0.113.5"}`, "203.0.113.5"},
		{"json ipv6 with whitespace", "{\"ip\": \" 2001:db8::1 \"}\n", "2001:db8::1"},
		{"bare ipv4", "203.0.113.5\n", "203.0.113.5"},
		{"bare ipv6", "2001:db8::1", "2001:db8::1"},
		{"json without ip", `{"error":"x"}`, ""},
		{"garbage", "<html>", ""},
		{"empty", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseMyIPBody([]byte(tc.body)); got != tc.want {
				t.Fatalf("parseMyIPBody(%q) = %q, want %q", tc.body, got, tc.want)
			}
		})
	}
}
