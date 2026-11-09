package helps

import (
	stdtls "crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"strings"

	"context"

	tls "github.com/refraction-networking/utls"
	internalcache "github.com/router-for-me/CLIProxyAPI/v8/internal/cache"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/httpwire"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/proxyutil"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/proxy"
)

// IsOpencodeUpstreamHost reports whether host belongs to the opencode.ai
// inference plane (the apex domain or any subdomain). OpenCode's free tier
// gates requests by TLS fingerprint, so this plane needs the OpenCode
// ClientHello emitted by opencodeDialTLSContext.
func IsOpencodeUpstreamHost(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return false
	}
	return host == "opencode.ai" || strings.HasSuffix(host, ".opencode.ai")
}

// opencodeSessionCacheCapacity bounds the per-transport TLS session cache for
// the OpenCode inference plane.
const opencodeSessionCacheCapacity = 32

// newOpencodeTLSConfigWithRoots builds the uTLS config for one inference-plane
// dial. OmitEmptyPsk keeps the pre_shared_key extension silent until a session
// is cached, so an unresumed ClientHello stays byte-identical to the captured
// native handshake. PreferSkipResumptionOnNilExtension turns uTLS's HelloCustom
// "resume without the matching extension" panic into a skipped resumption.
func newOpencodeTLSConfigWithRoots(host string, sessionCache tls.ClientSessionCache, roots *x509.CertPool) *tls.Config {
	return &tls.Config{
		ServerName:                         host,
		RootCAs:                            roots,
		ClientSessionCache:                 sessionCache,
		OmitEmptyPsk:                       true,
		PreferSkipResumptionOnNilExtension: true,
	}
}

// opencodeTLSClientHelloSpec reproduces the Node.js/OpenSSL 3.x ClientHello
// captured from the real opencode CLI (SNI opencode.ai). The static fields are
// pinned by internal/runtime/executor/helps/testdata/opencode_client_hello.bin;
// opencode_utls_test.go asserts the emitted handshake against them.
//
// Two extensions are emitted through tls.GenericExtension because they are not
// named types in uTLS: 0x0023 is the padding placeholder OpenSSL advertises
// with an empty body here, and 0x0012 is the RFC 8446 renegotiation_info
// marker that TLS 1.3 clients must send empty. The other "custom-looking"
// extensions map to standard uTLS types: 0xff01 is the RFC 5746 renegotiation
// info (body 00) and 0x0005 is the OCSP status_request (body 0100000000).
func opencodeTLSClientHelloSpec() *tls.ClientHelloSpec {
	return &tls.ClientHelloSpec{
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,                        // 0x1301
			tls.TLS_AES_256_GCM_SHA384,                        // 0x1302
			tls.TLS_CHACHA20_POLY1305_SHA256,                  // 0x1303
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,       // 0xc02b
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,         // 0xc02f
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,       // 0xc02c
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,         // 0xc030
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, // 0xcca9
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,   // 0xcca8
			0xc009,                              // ECDHE_RSA_WITH_AES_128_CBC_SHA; the uTLS constant with this value is misnamed
			0xc013,                              // ECDHE_RSA_WITH_AES_128_CBC_SHA256; the uTLS constant with this value is misnamed
			0xc00a,                              // ECDHE_ECDSA_WITH_AES_128_CBC_SHA; the uTLS constant with this value is misnamed
			0xc014,                              // ECDHE_RSA_WITH_AES_256_CBC_SHA384; the uTLS constant with this value is misnamed
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256, // 0x009c
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384, // 0x009d
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,    // 0x002f
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,    // 0x0035
		},
		CompressionMethods: []uint8{0},
		Extensions: []tls.TLSExtension{
			&tls.SNIExtension{},                  // 0x0000
			&tls.ExtendedMasterSecretExtension{}, // 0x0017
			&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient}, // 0xff01, body 00
			&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
				tls.X25519MLKEM768, // 0x11ec
				tls.X25519,         // 0x001d
				tls.CurveP256,      // 0x0017
				tls.CurveP384,      // 0x0018
			}},
			&tls.SupportedPointsExtension{SupportedPoints: []byte{0}}, // 0x000b
			&tls.GenericExtension{Id: 0x0023, Data: nil},              // 0x0023 padding placeholder, empty body
			&tls.ALPNExtension{AlpnProtocols: []string{"http/1.1"}},   // 0x0010
			&tls.StatusRequestExtension{},                             // 0x0005, body 0100000000
			&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
				tls.ECDSAWithP256AndSHA256, // 0x0403
				tls.PSSWithSHA256,          // 0x0804
				tls.PKCS1WithSHA256,        // 0x0401
				tls.ECDSAWithP384AndSHA384, // 0x0503
				tls.PSSWithSHA384,          // 0x0805
				tls.PKCS1WithSHA384,        // 0x0501
				tls.PSSWithSHA512,          // 0x0806
				tls.PKCS1WithSHA512,        // 0x0601
				tls.Ed25519,                // 0x0807
				tls.ECDSAWithP521AndSHA512, // 0x0603
				tls.PKCS1WithSHA1,          // 0x0201
			}},
			&tls.GenericExtension{Id: 0x0012, Data: nil}, // 0x0012 RFC 8446 renegotiation_info, empty body
			&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
				{Group: tls.X25519MLKEM768}, // 0x11ec; ApplyPreset generates the hybrid key data
				{Group: tls.X25519},         // 0x001d; ApplyPreset generates the fallback key data
			}},
			&tls.PSKKeyExchangeModesExtension{Modes: []uint8{tls.PskModeDHE}},                       // 0x002d
			&tls.SupportedVersionsExtension{Versions: []uint16{tls.VersionTLS13, tls.VersionTLS12}}, // 0x002b
			// pre_shared_key MUST be the final extension (RFC 8446 4.2.11).
			// It contributes zero bytes until a cached session exists.
			&tls.UtlsPreSharedKeyExtension{},
		},
	}
}

// opencodeInferenceHeaderOrder is the HTTP/1.1 header order for requests to
// opencode.ai. No full captured HTTP request is committed with the fingerprint
// data, so this is a canonical ordering modeled on the opencode CLI's header
// family (credential, content, UA, tracing, acceptance, transport trailers).
// Headers absent from the list keep their original relative order after it.
var opencodeInferenceHeaderOrder = []string{
	"Authorization",
	"Content-Type",
	"User-Agent",
	"Accept",
	"B3",
	"Traceparent",
	"Connection",
	"Host",
	"Accept-Encoding",
	"Content-Length",
}

func opencodeRequestHeaderOrder(_, _ string) []string {
	return opencodeInferenceHeaderOrder
}

const opencodeRoundTripperCacheCapacity = 64

var opencodeRoundTripperCache = internalcache.NewBoundedLRU[string, http.RoundTripper](
	opencodeRoundTripperCacheCapacity,
	func(_ string, roundTripper http.RoundTripper) {
		if transport, ok := roundTripper.(interface{ CloseIdleConnections() }); ok {
			transport.CloseIdleConnections()
		}
	},
)

// CachedOpencodeRoundTripper returns the opencode.ai-plane uTLS transport for
// one proxy setting. The transport is safe to install for any upstream host:
// its DialTLSContext applies the OpenCode ClientHello only to opencode.ai and
// subdomains, and plain-TLS-dials every other host.
func CachedOpencodeRoundTripper(proxyURL string) http.RoundTripper {
	return opencodeRoundTripperCache.GetOrAdd(proxyURL, func() http.RoundTripper {
		return newOpencodeRoundTripper(proxyURL)
	})
}

func newOpencodeRoundTripper(proxyURL string) http.RoundTripper {
	return newOpencodeRoundTripperForDialer(opencodeDialer(proxyURL))
}

// opencodeDialer resolves the dialer the OpenCode transport uses for one proxy
// setting, mirroring claudeCodeDialer so both keep the same proxy semantics.
func opencodeDialer(proxyURL string) proxy.Dialer {
	var dialer proxy.Dialer = proxy.Direct
	if proxyURL != "" {
		proxyDialer, mode, errBuild := proxyutil.BuildDialer(proxyURL)
		if errBuild != nil {
			log.Errorf("opencode tls: failed to configure proxy dialer for %q: %v", proxyutil.Redact(proxyURL), errBuild)
		} else if mode != proxyutil.ModeInherit && proxyDialer != nil {
			dialer = proxyDialer
		}
	}
	return dialer
}

// newOpencodeRoundTripperForDialer builds the OpenCode transport on top of an
// already-resolved dialer. It is split out from newOpencodeRoundTripper so
// tests can inject in-memory or redirected connections.
func newOpencodeRoundTripperForDialer(dialer proxy.Dialer) *http.Transport {
	return newOpencodeRoundTripperForDialerAndRoots(dialer, nil)
}

func newOpencodeRoundTripperForDialerAndRoots(dialer proxy.Dialer, roots *x509.CertPool) *http.Transport {
	// The cache is scoped to this round tripper, which is already keyed by proxy,
	// so resumption never crosses proxy boundaries.
	sessionCache := tls.NewLRUClientSessionCache(opencodeSessionCacheCapacity)

	return &http.Transport{
		ForceAttemptHTTP2: false,
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return opencodeDialTLSContext(ctx, dialer, sessionCache, roots, network, addr)
		},
	}
}

// opencodeDialTLSContext dials one TLS connection for the OpenCode transport.
// opencode.ai hosts get the captured OpenCode ClientHello; every other host
// falls back to standard crypto/tls so the transport can be installed broadly
// without changing fingerprints elsewhere.
func opencodeDialTLSContext(
	ctx context.Context,
	dialer proxy.Dialer,
	sessionCache tls.ClientSessionCache,
	roots *x509.CertPool,
	network, addr string,
) (net.Conn, error) {
	var (
		conn net.Conn
		err  error
	)
	if contextDialer, ok := dialer.(proxy.ContextDialer); ok {
		conn, err = contextDialer.DialContext(ctx, network, addr)
	} else {
		conn, err = dialer.Dial(network, addr)
	}
	if err != nil {
		return nil, fmt.Errorf("opencode tls: dial upstream: %w", err)
	}
	conn = stampProxyKeepAlive(conn)

	host, _, errSplit := net.SplitHostPort(addr)
	if errSplit != nil {
		if errClose := conn.Close(); errClose != nil {
			log.Debugf("opencode tls: close failed connection: %v", errClose)
		}
		return nil, fmt.Errorf("opencode tls: split upstream address: %w", errSplit)
	}

	handshakeCtx, cancelHandshake := handshakeContext(ctx)
	defer cancelHandshake()

	if !IsOpencodeUpstreamHost(host) {
		plainConn := stdtls.Client(conn, &stdtls.Config{ServerName: host, RootCAs: roots})
		if errHandshake := plainConn.HandshakeContext(handshakeCtx); errHandshake != nil {
			errHandshake = classifyHandshakeError(ctx, handshakeCtx, errHandshake)
			if errClose := conn.Close(); errClose != nil {
				log.Debugf("opencode tls: close connection after handshake failure: %v", errClose)
			}
			return nil, fmt.Errorf("opencode tls: plain TLS handshake: %w", errHandshake)
		}
		return plainConn, nil
	}

	tlsConn := tls.UClient(conn, newOpencodeTLSConfigWithRoots(host, sessionCache, roots), tls.HelloCustom)
	if errPreset := tlsConn.ApplyPreset(opencodeTLSClientHelloSpec()); errPreset != nil {
		if errClose := tlsConn.Close(); errClose != nil {
			log.Debugf("opencode tls: close connection after preset failure: %v", errClose)
		}
		return nil, fmt.Errorf("opencode tls: apply OpenCode ClientHello: %w", errPreset)
	}
	if errHandshake := tlsConn.HandshakeContext(handshakeCtx); errHandshake != nil {
		errHandshake = classifyHandshakeError(ctx, handshakeCtx, errHandshake)
		if errClose := tlsConn.Close(); errClose != nil {
			log.Debugf("opencode tls: close connection after handshake failure: %v", errClose)
		}
		return nil, fmt.Errorf("opencode tls: handshake upstream: %w", errHandshake)
	}
	return httpwire.NewOrderedRequestConn(tlsConn, opencodeRequestHeaderOrder), nil
}
