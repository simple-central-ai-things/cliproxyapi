package pluginhost

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

type opencodeRouteRoundTripper struct {
	label string
}

func (r opencodeRouteRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"X-Test-Route": []string{r.label}},
		Body:       io.NopCloser(strings.NewReader("{}")),
		Request:    req,
	}, nil
}

func TestOpencodeFingerprintRoundTripperSelectsTransport(t *testing.T) {
	t.Parallel()

	roundTripper := &opencodeFingerprintRoundTripper{
		opencode: opencodeRouteRoundTripper{label: "opencode"},
		base:     opencodeRouteRoundTripper{label: "base"},
	}
	tests := []struct {
		name string
		url  string
		want string
	}{
		{name: "OpenCode apex HTTPS", url: "https://opencode.ai/zen/v1/models", want: "opencode"},
		{name: "OpenCode subdomain HTTPS", url: "https://zen.opencode.ai/v1/models", want: "opencode"},
		{name: "OpenCode HTTP falls through", url: "http://opencode.ai/v1/models", want: "base"},
		{name: "Lookalike domain falls through", url: "https://opencode.ai.example/v1/models", want: "base"},
		{name: "Other provider falls through", url: "https://api.anthropic.com/v1/messages", want: "base"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, errRequest := http.NewRequest(http.MethodGet, tt.url, nil)
			if errRequest != nil {
				t.Fatal(errRequest)
			}
			resp, errRoundTrip := roundTripper.RoundTrip(req)
			if errRoundTrip != nil {
				t.Fatal(errRoundTrip)
			}
			defer func() {
				if errClose := resp.Body.Close(); errClose != nil {
					t.Errorf("close response body: %v", errClose)
				}
			}()
			if got := resp.Header.Get("X-Test-Route"); got != tt.want {
				t.Fatalf("route = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestHostHTTPClientInstallsOpencodeFingerprintTransport proves the bridge
// installs the host-gated fingerprint transport based on the request
// DESTINATION (opencode.ai), not the provider name — the generic host.http.do
// path has no provider context yet must still fingerprint opencode.ai.
func TestHostHTTPClientInstallsOpencodeFingerprintTransport(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name     string
		provider string
		url      string
		want     bool
	}{
		{name: "opencode provider to opencode.ai installs the fingerprint", provider: "opencode-go", url: "https://opencode.ai/zen/v1/models", want: true},
		{name: "no provider context to opencode.ai installs the fingerprint", provider: "", url: "https://opencode.ai/inference/openai/v1/chat/completions", want: true},
		{name: "other provider to a non-opencode host keeps the bridge transport", provider: "commandcode", url: "https://api.commandcode.ai/provider/v1/models", want: false},
		{name: "opencode provider to a non-opencode host keeps the bridge transport", provider: "opencode-go", url: "https://api.anthropic.com/v1/messages", want: false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			hostClient := New().newHTTPClientWithProxy(nil, "", tt.provider).(*hostHTTPClient)
			httpReq, errRequest := http.NewRequestWithContext(t.Context(), http.MethodGet, tt.url, nil)
			if errRequest != nil {
				t.Fatal(errRequest)
			}
			client, cleanup, errClient := hostClient.newHTTPClientForRequest(t.Context(), nil, pluginapi.HTTPRequest{
				URL: tt.url,
			}, httpReq)
			if errClient != nil {
				t.Fatalf("newHTTPClientForRequest error = %v", errClient)
			}
			if cleanup != nil {
				defer cleanup()
			}

			_, wrapped := client.Transport.(*opencodeFingerprintRoundTripper)
			if wrapped != tt.want {
				t.Fatalf("transport type = %T, want fingerprint wrapper = %v", client.Transport, tt.want)
			}
			if tt.want {
				wrapper := client.Transport.(*opencodeFingerprintRoundTripper)
				if wrapper.base == nil || wrapper.opencode == nil {
					t.Fatal("fingerprint wrapper is missing the opencode or base transport")
				}
			}
		})
	}
}
