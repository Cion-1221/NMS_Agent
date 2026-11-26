package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func genTestCA(t *testing.T, cn string) (*x509.Certificate, *ecdsa.PrivateKey, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	caPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	return caCert, key, caPEM
}

func genTestLeaf(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, cn string, server bool) (certPEM, keyPEM string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	eku := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	var ips []net.IP
	if server {
		eku = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		ips = []net.IP{net.ParseIP("127.0.0.1")}
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano() + 1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(12 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  eku,
		IPAddresses:  ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
}

func TestEnrollAndCABundleHotReload(t *testing.T) {
	ca1, caKey1, caPEM1 := genTestCA(t, "CA-1")
	ca2, caKey2, caPEM2 := genTestCA(t, "CA-2")
	clientCert1, clientKey1 := genTestLeaf(t, ca1, caKey1, "AGT-0001", false)

	var gotReq enrollRequest
	enrollSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&gotReq); err != nil {
			t.Errorf("decode req: %v", err)
		}
		_ = json.NewEncoder(w).Encode(enrollResponse{
			AgentID:    "AGT-0001",
			CertPEM:    clientCert1,
			KeyPEM:     clientKey1,
			CACertPEM:  caPEM1,
			CertExpiry: time.Now().Add(12 * time.Hour),
			SyncPort:   8444,
		})
	}))
	defer enrollSrv.Close()

	dir := t.TempDir()
	agentID, err := Enroll(enrollSrv.URL, "tok-123", "edge-hkg-01", "HKG", map[string]string{"role": "edge"}, dir, true)
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if agentID != "AGT-0001" || gotReq.Region != "HKG" || gotReq.Tags["role"] != "edge" {
		t.Fatalf("unexpected enroll result id=%q req=%+v", agentID, gotReq)
	}
	if !HasCerts(dir) {
		t.Fatal("HasCerts=false after Enroll")
	}

	fp1 := CAFingerprints(dir)
	if len(fp1) != 16 {
		t.Fatalf("expected 16-char CA fingerprint, got %q", fp1)
	}

	// Unchanged bundle must report changed=false.
	changed, err := UpdateCABundle(dir, caPEM1)
	if err != nil || changed {
		t.Fatalf("expected changed=false on identical CA bundle, got changed=%v err=%v", changed, err)
	}

	// Pre-distribute CA-1 + CA-2 bundle, then stand up mTLS server signed by CA-2!
	changed, err = UpdateCABundle(dir, caPEM1+"\n"+caPEM2)
	if err != nil || !changed {
		t.Fatalf("UpdateCABundle(CA1+CA2): changed=%v err=%v", changed, err)
	}
	fpsBoth := CAFingerprints(dir)
	if !strings.Contains(fpsBoth, ",") {
		t.Fatalf("expected two comma-separated fingerprints, got %q", fpsBoth)
	}

	// Stand up mTLS sync server whose server cert is signed by CA-2 while still trusting CA-1 client certs.
	srvCert2, srvKey2 := genTestLeaf(t, ca2, caKey2, "127.0.0.1", true)
	srvPair2, err := tls.X509KeyPair([]byte(srvCert2), []byte(srvKey2))
	if err != nil {
		t.Fatal(err)
	}
	clientPool := x509.NewCertPool()
	clientPool.AddCert(ca1)
	clientPool.AddCert(ca2)

	clientCert2, clientKey2 := genTestLeaf(t, ca2, caKey2, "AGT-0001", false)
	syncSrv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/agent-sync/renew-cert" {
			_ = json.NewEncoder(w).Encode(renewResponse{
				AgentID:   "AGT-0001",
				CertPEM:   clientCert2,
				KeyPEM:    clientKey2,
				CACertPEM: caPEM2,
			})
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	syncSrv.TLS = &tls.Config{
		Certificates: []tls.Certificate{srvPair2},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientPool,
	}
	syncSrv.StartTLS()
	defer syncSrv.Close()

	mtlsClient, err := NewMTLSClient(dir, 5*time.Second)
	if err != nil {
		t.Fatalf("NewMTLSClient: %v", err)
	}
	defer mtlsClient.CloseIdleConnections()

	// Agent seamlessly connects to CA-2 server and renews its client cert onto CA-2!
	if err := Renew(mtlsClient, syncSrv.URL, dir); err != nil {
		t.Fatalf("Renew against rotated CA-2 server: %v", err)
	}
	mtlsClient.CloseIdleConnections()

	// Verify reloader picks up the renewed client cert and CA-2-only bundle.
	if got := CAFingerprints(dir); strings.Contains(got, ",") || got == fp1 {
		t.Fatalf("expected single CA-2 fingerprint after renew, got %q", got)
	}
	resp, err := mtlsClient.Get(syncSrv.URL + "/ping")
	if err != nil {
		t.Fatalf("mTLS GET after renew: %v", err)
	}
	_ = resp.Body.Close()

	// Ensure invalid PEM is rejected without corrupting ca.crt on disk.
	before, _ := os.ReadFile(filepath.Join(dir, fileCACert))
	if _, err := UpdateCABundle(dir, "not-a-valid-pem"); err == nil {
		t.Fatal("expected error on invalid CA bundle PEM")
	}
	after, _ := os.ReadFile(filepath.Join(dir, fileCACert))
	if string(before) != string(after) {
		t.Fatal("ca.crt was modified despite invalid PEM")
	}
}
