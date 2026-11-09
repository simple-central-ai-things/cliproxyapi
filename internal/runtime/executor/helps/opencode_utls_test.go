package helps

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	stdtls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/proxy"
)

// opencodeTLSFingerprintFixture pins the static fields of the ClientHello
// captured from the real opencode CLI against opencode.ai (see
// testdata/opencode_client_hello.bin and testdata/opencode_tls_fingerprint.txt).
// The reference JA3 is computed over version, cipher suites, extension IDs and
// supported groups only (no point formats), matching the committed reference.
type opencodeTLSFingerprintFixture struct {
	JA3                 string
	JA3MD5              string
	ALPN                []string
	CipherSuites        []uint16
	ExtensionTypes      []uint16
	ExtensionLengths    [][2]int
	SupportedGroups     []uint16
	PointFormats        []uint8
	SignatureAlgorithms []uint16
	SupportedVersions   []uint16
	KeyShareGroups      []uint16
}

func opencodeTLSFingerprintReference() opencodeTLSFingerprintFixture {
	return opencodeTLSFingerprintFixture{
		JA3:    "771,4865,4866,4867,49195,49199,49196,49200,52393,52392,49161,49171,49162,49172,156,157,47,53,0,23,65281,10,11,35,16,5,13,18,51,45,43,4588,29,23,24",
		JA3MD5: "c02e5bb4c114c8348e73c3e0f035f21c",
		ALPN:   []string{"http/1.1"},
		CipherSuites: []uint16{
			0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8,
			0xc009, 0xc013, 0xc00a, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
		},
		ExtensionTypes: []uint16{
			0x0000, // SNI
			0x0017, // extended_master_secret
			0xff01, // RFC 5746 renegotiation_info (body 00)
			0x000a, // supported_groups
			0x000b, // ec_point_formats
			0x0023, // padding placeholder (empty body)
			0x0010, // ALPN
			0x0005, // OCSP status_request (body 0100000000)
			0x000d, // signature_algorithms
			0x0012, // RFC 8446 renegotiation_info (empty body)
			0x0033, // key_share
			0x002d, // psk_key_exchange_modes
			0x002b, // supported_versions
		},
		ExtensionLengths: [][2]int{
			{0x0000, 16}, {0x0017, 0}, {0xff01, 1}, {0x000a, 10}, {0x000b, 2},
			{0x0023, 0}, {0x0010, 11}, {0x0005, 5}, {0x000d, 24}, {0x0012, 0},
			{0x0033, 1258}, {0x002d, 2}, {0x002b, 5},
		},
		SupportedGroups:     []uint16{0x11ec, 0x001d, 0x0017, 0x0018}, // X25519MLKEM768, X25519, P-256, P-384
		PointFormats:        []uint8{0},
		SignatureAlgorithms: []uint16{0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0807, 0x0603, 0x0201},
		SupportedVersions:   []uint16{0x0304, 0x0303},
		KeyShareGroups:      []uint16{0x11ec, 0x001d},
	}
}

type opencodeClientHelloSummary struct {
	CipherSuites        []uint16
	ExtensionTypes      []uint16
	ALPN                []string
	SupportedGroups     []uint16
	PointFormats        []uint8
	SignatureAlgorithms []uint16
	SupportedVersions   []uint16
	KeyShareGroups      []uint16
	JA3                 string
	JA3MD5              string
}

func summarizeOpencodeClientHelloSpec(t *testing.T, spec *utls.ClientHelloSpec) opencodeClientHelloSummary {
	t.Helper()
	summary := opencodeClientHelloSummary{CipherSuites: append([]uint16(nil), spec.CipherSuites...)}
	for _, extension := range spec.Extensions {
		switch ext := extension.(type) {
		case *utls.SNIExtension:
			summary.ExtensionTypes = append(summary.ExtensionTypes, 0x0000)
		case *utls.ExtendedMasterSecretExtension:
			summary.ExtensionTypes = append(summary.ExtensionTypes, 0x0017)
		case *utls.RenegotiationInfoExtension:
			summary.ExtensionTypes = append(summary.ExtensionTypes, 0xff01)
		case *utls.SupportedCurvesExtension:
			summary.ExtensionTypes = append(summary.ExtensionTypes, 0x000a)
			for _, curve := range ext.Curves {
				summary.SupportedGroups = append(summary.SupportedGroups, uint16(curve))
			}
		case *utls.SupportedPointsExtension:
			summary.ExtensionTypes = append(summary.ExtensionTypes, 0x000b)
			summary.PointFormats = append(summary.PointFormats, ext.SupportedPoints...)
		case *utls.GenericExtension:
			summary.ExtensionTypes = append(summary.ExtensionTypes, ext.Id)
		case *utls.SessionTicketExtension:
			// 0x0023 is IANA-registered as both padding and session_ticket; the
			// fingerprinter maps the capture's empty padding placeholder here.
			summary.ExtensionTypes = append(summary.ExtensionTypes, 0x0023)
		case *utls.SCTExtension:
			// 0x0012 is IANA-registered as both SCT and the RFC 8446
			// renegotiation_info marker; the fingerprinter maps the capture's
			// empty marker here.
			summary.ExtensionTypes = append(summary.ExtensionTypes, 0x0012)
		case *utls.ALPNExtension:
			summary.ExtensionTypes = append(summary.ExtensionTypes, 0x0010)
			summary.ALPN = append(summary.ALPN, ext.AlpnProtocols...)
		case *utls.StatusRequestExtension:
			summary.ExtensionTypes = append(summary.ExtensionTypes, 0x0005)
		case *utls.SignatureAlgorithmsExtension:
			summary.ExtensionTypes = append(summary.ExtensionTypes, 0x000d)
			for _, algorithm := range ext.SupportedSignatureAlgorithms {
				summary.SignatureAlgorithms = append(summary.SignatureAlgorithms, uint16(algorithm))
			}
		case *utls.KeyShareExtension:
			summary.ExtensionTypes = append(summary.ExtensionTypes, 0x0033)
			for _, keyShare := range ext.KeyShares {
				summary.KeyShareGroups = append(summary.KeyShareGroups, uint16(keyShare.Group))
			}
		case *utls.PSKKeyExchangeModesExtension:
			summary.ExtensionTypes = append(summary.ExtensionTypes, 0x002d)
		case *utls.SupportedVersionsExtension:
			summary.ExtensionTypes = append(summary.ExtensionTypes, 0x002b)
			summary.SupportedVersions = append(summary.SupportedVersions, ext.Versions...)
		case *utls.UtlsPreSharedKeyExtension:
			// Zero bytes on the wire until a session is cached, so it never
			// appears in a fresh capture.
		default:
			t.Fatalf("unexpected ClientHello extension type %T", extension)
		}
	}
	// The reference JA3 covers ciphers, extension IDs and supported groups
	// only (the committed reference omits point formats).
	summary.JA3 = fmt.Sprintf("771,%s,%s,%s",
		uint16ListToCSV(summary.CipherSuites),
		uint16ListToCSV(summary.ExtensionTypes),
		uint16ListToCSV(summary.SupportedGroups))
	digest := md5.Sum([]byte(summary.JA3)) // #nosec G401 -- JA3 requires MD5.
	summary.JA3MD5 = hex.EncodeToString(digest[:])
	return summary
}

func uint16ListToCSV(values []uint16) string {
	parts := make([]string, len(values))
	for index, value := range values {
		parts[index] = strconv.Itoa(int(value))
	}
	return strings.Join(parts, ",")
}

// fixedConnDialer always returns one pre-bound connection, so the transport's
// host logic (SNI, fingerprint gate) runs while the bytes land on an in-memory
// pipe instead of the network. Fully offline.
type fixedConnDialer struct {
	conn net.Conn
}

func (d fixedConnDialer) Dial(string, string) (net.Conn, error) { return d.conn, nil }
func (d fixedConnDialer) DialContext(_ context.Context, _, _ string) (net.Conn, error) {
	return d.conn, nil
}

var _ proxy.ContextDialer = fixedConnDialer{}

// captureOpencodeTransportClientHello drives one request through the production
// DialTLSContext for the given upstream host and returns the TLS record bytes
// the server would see, without completing the handshake.
func captureOpencodeTransportClientHello(t *testing.T, host string, roots *x509.CertPool) []byte {
	t.Helper()

	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() {
		if errClose := clientConn.Close(); errClose != nil && !errors.Is(errClose, net.ErrClosed) && !errors.Is(errClose, io.ErrClosedPipe) {
			t.Errorf("close client pipe: %v", errClose)
		}
		if errClose := serverConn.Close(); errClose != nil && !errors.Is(errClose, net.ErrClosed) && !errors.Is(errClose, io.ErrClosedPipe) {
			t.Errorf("close server pipe: %v", errClose)
		}
	})

	transport := newOpencodeRoundTripperForDialerAndRoots(fixedConnDialer{conn: clientConn}, roots)
	req, errRequest := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://"+host+":443/", nil)
	if errRequest != nil {
		t.Fatal(errRequest)
	}

	roundTripDone := make(chan error, 1)
	go func() {
		respRoundTrip, errRoundTrip := transport.RoundTrip(req)
		if respRoundTrip != nil && respRoundTrip.Body != nil {
			_ = respRoundTrip.Body.Close()
		}
		roundTripDone <- errRoundTrip
	}()

	if errDeadline := serverConn.SetReadDeadline(time.Now().Add(5 * time.Second)); errDeadline != nil {
		t.Fatal(errDeadline)
	}
	header := make([]byte, 5)
	if _, errRead := io.ReadFull(serverConn, header); errRead != nil {
		t.Fatal(errRead)
	}
	payload := make([]byte, int(binary.BigEndian.Uint16(header[3:5])))
	if _, errRead := io.ReadFull(serverConn, payload); errRead != nil {
		t.Fatal(errRead)
	}
	if errClose := serverConn.Close(); errClose != nil {
		t.Fatal(errClose)
	}
	select {
	case <-roundTripDone:
	case <-time.After(5 * time.Second):
		t.Fatal("round trip did not exit after the capture connection closed")
	}
	return append(header, payload...)
}

func fingerprintOpencodeClientHello(t *testing.T, record []byte) *utls.ClientHelloSpec {
	t.Helper()
	// AllowBluntMimicry keeps the capture's 0x0012 and 0x0023 extensions as
	// generic ones so their exact position and body survive the parse.
	spec, errFingerprint := (&utls.Fingerprinter{AllowBluntMimicry: true}).FingerprintClientHello(record)
	if errFingerprint != nil {
		t.Fatal(errFingerprint)
	}
	return spec
}

func TestOpencodeRoundTripperAppliesPresetForOpencodeHost(t *testing.T) {
	t.Parallel()

	fixture := opencodeTLSFingerprintReference()
	record := captureOpencodeTransportClientHello(t, "opencode.ai", nil)

	if got := parseClientHelloExtensionLengths(t, record); !reflect.DeepEqual(got, fixture.ExtensionLengths) {
		t.Fatalf("extension lengths = %v, want %v", got, fixture.ExtensionLengths)
	}

	actual := summarizeOpencodeClientHelloSpec(t, fingerprintOpencodeClientHello(t, record))
	if !reflect.DeepEqual(actual.CipherSuites, fixture.CipherSuites) {
		t.Fatalf("cipher suites = %v, want %v", actual.CipherSuites, fixture.CipherSuites)
	}
	if !reflect.DeepEqual(actual.ExtensionTypes, fixture.ExtensionTypes) {
		t.Fatalf("extension types = %v, want %v", actual.ExtensionTypes, fixture.ExtensionTypes)
	}
	if !reflect.DeepEqual(actual.ALPN, fixture.ALPN) {
		t.Fatalf("ALPN = %v, want %v", actual.ALPN, fixture.ALPN)
	}
	if !reflect.DeepEqual(actual.SupportedGroups, fixture.SupportedGroups) {
		t.Fatalf("supported groups = %v, want %v", actual.SupportedGroups, fixture.SupportedGroups)
	}
	if !reflect.DeepEqual(actual.PointFormats, fixture.PointFormats) {
		t.Fatalf("point formats = %v, want %v", actual.PointFormats, fixture.PointFormats)
	}
	if !reflect.DeepEqual(actual.SignatureAlgorithms, fixture.SignatureAlgorithms) {
		t.Fatalf("signature algorithms = %v, want %v", actual.SignatureAlgorithms, fixture.SignatureAlgorithms)
	}
	if !reflect.DeepEqual(actual.SupportedVersions, fixture.SupportedVersions) {
		t.Fatalf("supported versions = %v, want %v", actual.SupportedVersions, fixture.SupportedVersions)
	}
	if !reflect.DeepEqual(actual.KeyShareGroups, fixture.KeyShareGroups) {
		t.Fatalf("key share groups = %v, want %v", actual.KeyShareGroups, fixture.KeyShareGroups)
	}
	if actual.JA3 != fixture.JA3 || actual.JA3MD5 != fixture.JA3MD5 {
		t.Fatalf("JA3 = %q (%s), want %q (%s)", actual.JA3, actual.JA3MD5, fixture.JA3, fixture.JA3MD5)
	}

	assertOpencodeReferenceCaptureMatchesFixture(t, fixture)
}

// TestOpencodeRoundTripperFallsBackToPlainTLSForOtherHosts proves the transport
// only fingerprints opencode.ai and keeps a standard crypto/tls ClientHello
// elsewhere. The padding placeholder and the RFC 8446 renegotiation_info marker
// exist only in the OpenCode preset, so their absence proves plain TLS.
func TestOpencodeRoundTripperFallsBackToPlainTLSForOtherHosts(t *testing.T) {
	t.Parallel()

	record := captureOpencodeTransportClientHello(t, "example.com", nil)
	spec := fingerprintOpencodeClientHello(t, record)
	for _, extension := range spec.Extensions {
		if generic, ok := extension.(*utls.GenericExtension); ok {
			for _, fingerprintOnly := range []uint16{0x0012, 0x0023} {
				if generic.Id == fingerprintOnly {
					t.Fatalf("non-opencode host emitted fingerprint-only extension 0x%04x", generic.Id)
				}
			}
		}
	}
}

// TestOpencodeRoundTripperCompletesHandshakeAgainstRealServer runs a full TLS 1.3
// handshake plus an HTTP round trip against a loopback crypto/tls server, proving
// the hybrid X25519MLKEM768 key share and the custom extensions are wire-safe.
func TestOpencodeRoundTripperCompletesHandshakeAgainstRealServer(t *testing.T) {
	t.Parallel()

	roots, leafCert := opencodeTestCertificate(t, "opencode.ai")

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	server.TLS = &stdtls.Config{Certificates: []stdtls.Certificate{leafCert}, NextProtos: []string{"http/1.1"}}
	server.StartTLS()
	t.Cleanup(server.Close)

	transport := newOpencodeRoundTripperForDialerAndRoots(
		redirectedDialer{target: server.Listener.Addr().String()},
		roots,
	)
	client := &http.Client{Transport: transport}
	resp, errDo := client.Get("https://opencode.ai" + serverPort(server.Listener) + "/")
	if errDo != nil {
		t.Fatal(errDo)
	}
	if errClose := resp.Body.Close(); errClose != nil {
		t.Fatal(errClose)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

type redirectedDialer struct {
	target string
}

func (d redirectedDialer) Dial(network, _ string) (net.Conn, error) {
	return (&net.Dialer{Timeout: 5 * time.Second}).Dial(network, d.target)
}

func (d redirectedDialer) DialContext(ctx context.Context, network, _ string) (net.Conn, error) {
	return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, d.target)
}

var _ proxy.ContextDialer = redirectedDialer{}

// opencodeTestCertificate builds an in-memory CA and a leaf certificate for one
// DNS name, both usable offline.
func opencodeTestCertificate(t *testing.T, name string) (*x509.CertPool, stdtls.Certificate) {
	t.Helper()

	caKey, errKey := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if errKey != nil {
		t.Fatal(errKey)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "opencode test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caDER, errCert := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if errCert != nil {
		t.Fatal(errCert)
	}
	caCert, errParse := x509.ParseCertificate(caDER)
	if errParse != nil {
		t.Fatal(errParse)
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	leafKey, errKey := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if errKey != nil {
		t.Fatal(errKey)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{name},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, errCert := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	if errCert != nil {
		t.Fatal(errCert)
	}
	return pool, stdtls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}
}

func serverPort(listener net.Listener) string {
	_, port, errSplit := net.SplitHostPort(listener.Addr().String())
	if errSplit != nil {
		return ""
	}
	return ":" + port
}

// assertOpencodeReferenceCaptureMatchesFixture keeps the fixture in sync with
// the committed reference capture by walking its extension block and comparing
// extension types and body lengths.
func assertOpencodeReferenceCaptureMatchesFixture(t *testing.T, fixture opencodeTLSFingerprintFixture) {
	t.Helper()

	path := filepath.Join("testdata", "opencode_client_hello.bin")
	data, errRead := os.ReadFile(path)
	if errRead != nil {
		t.Skipf("reference capture not available: %v", errRead)
	}
	// Anchor on the SNI extension carrying opencode.ai (host_name type, name
	// length 11): ext id, ext len, ServerNameList len, name type, host len.
	sniAnchor := []byte{0x00, 0x00, 0x00, 0x10, 0x00, 0x0e, 0x00, 0x00, 0x0b}
	anchor := indexBytes(data, sniAnchor)
	if anchor < 0 || !strings.Contains(string(data[anchor:anchor+len(sniAnchor)+11]), "opencode.ai") {
		t.Fatal("reference capture does not contain the opencode.ai SNI extension")
	}
	offset := anchor
	count := 0
	for count < len(fixture.ExtensionTypes) {
		if offset+4 > len(data) {
			break
		}
		extensionType := int(binary.BigEndian.Uint16(data[offset : offset+2]))
		extensionLength := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
		wantType := int(fixture.ExtensionTypes[count])
		if extensionType != wantType {
			t.Fatalf("reference extension %d = 0x%04x, want 0x%04x", count, extensionType, wantType)
		}
		// The reference's SNI body (opencode.ai) matches the emitted one; from
		// the second extension on the bodies must be byte-identical too.
		if count > 0 {
			wantLength := fixture.ExtensionLengths[count][1]
			if extensionLength != wantLength {
				t.Fatalf("reference extension 0x%04x body length = %d, want %d", extensionType, extensionLength, wantLength)
			}
		}
		offset += 4 + extensionLength
		count++
	}
	if count != len(fixture.ExtensionTypes) {
		t.Fatalf("reference capture carries %d extensions, want %d", count, len(fixture.ExtensionTypes))
	}
}

func indexBytes(data, pattern []byte) int {
	for index := 0; index+len(pattern) <= len(data); index++ {
		if string(data[index:index+len(pattern)]) == string(pattern) {
			return index
		}
	}
	return -1
}

func TestIsOpencodeUpstreamHost(t *testing.T) {
	t.Parallel()

	tests := []struct {
		host string
		want bool
	}{
		{host: "opencode.ai", want: true},
		{host: "OPENCODE.AI", want: true},
		{host: "zen.opencode.ai", want: true},
		{host: "api.opencode.ai", want: true},
		{host: "opencode.ai.example", want: false},
		{host: "evilopencode.ai", want: false},
		{host: "example.com", want: false},
		{host: "", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			if got := IsOpencodeUpstreamHost(tt.host); got != tt.want {
				t.Fatalf("IsOpencodeUpstreamHost(%q) = %v, want %v", tt.host, got, tt.want)
			}
		})
	}
}

func TestCachedOpencodeRoundTripperReusesTransport(t *testing.T) {
	t.Parallel()

	const proxyURL = "http://127.0.0.1:29761"
	first := CachedOpencodeRoundTripper(proxyURL)
	second := CachedOpencodeRoundTripper(proxyURL)
	if first != second {
		t.Fatal("OpenCode transport cache returned different transports for one proxy")
	}
	transport, ok := first.(*http.Transport)
	if !ok {
		t.Fatalf("OpenCode transport type = %T, want *http.Transport", first)
	}
	if transport.ForceAttemptHTTP2 {
		t.Fatal("OpenCode transport must not force HTTP/2")
	}
	if transport.DialTLSContext == nil {
		t.Fatal("OpenCode transport is missing the fingerprint DialTLSContext")
	}
}
