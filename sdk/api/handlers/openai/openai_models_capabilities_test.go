package openai

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers"
)

// TestOpenAIModelsExposesPluginCapabilities verifies the OpenAI /v1/models
// handler does not drop the capability metadata a provider plugin reported via
// its ModelInfo: context window (context_length) plus the vision/reasoning
// markers and modalities. The base id/object/created/owned_by contract and the
// model id format are unchanged.
func TestOpenAIModelsExposesPluginCapabilities(t *testing.T) {
	gin.SetMode(gin.TestMode)

	modelRegistry := registry.GetGlobalRegistry()
	clientID := "openai-plugin-capabilities-test"
	modelRegistry.RegisterClient(clientID, "plugin-cap", []*registry.ModelInfo{{
		ID:                       "plugin-cap/model",
		Object:                   "model",
		OwnedBy:                  "plugin-cap",
		Type:                     "openai",
		Created:                  1700000000,
		ContextLength:            262144,
		MaxCompletionTokens:      64000,
		SupportedInputModalities: []string{"text", "image"},
		Thinking:                 &registry.ThinkingSupport{Levels: []string{"low", "high"}},
	}})
	t.Cleanup(func() {
		modelRegistry.UnregisterClient(clientID)
	})

	handler := NewOpenAIAPIHandler(handlers.NewBaseAPIHandlers(&config.SDKConfig{}, nil))

	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodGet, "/v1/models", nil)

	handler.OpenAIModels(c)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", recorder.Code, http.StatusOK, recorder.Body.String())
	}

	var resp struct {
		Object string           `json:"object"`
		Data   []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode /v1/models response: %v; body=%s", err, recorder.Body.String())
	}
	if resp.Object != "list" {
		t.Fatalf("object = %q, want list", resp.Object)
	}

	var target map[string]any
	for _, m := range resp.Data {
		if id, _ := m["id"].(string); id == "plugin-cap/model" {
			target = m
			break
		}
	}
	if target == nil {
		t.Fatalf("expected plugin-cap/model in response, got %s", recorder.Body.String())
	}

	if got := target["id"]; got != "plugin-cap/model" {
		t.Errorf("id = %v, want plugin-cap/model (id format must not change)", got)
	}
	if got := target["object"]; got != "model" {
		t.Errorf("object = %v, want model", got)
	}
	if got := target["owned_by"]; got != "plugin-cap" {
		t.Errorf("owned_by = %v, want plugin-cap", got)
	}
	if got := target["created"]; got != float64(1700000000) {
		t.Errorf("created = %v, want 1700000000", got)
	}

	if got := target["context_length"]; got != float64(262144) {
		t.Errorf("context_length = %v, want 262144", got)
	}
	if got := target["max_completion_tokens"]; got != float64(64000) {
		t.Errorf("max_completion_tokens = %v, want 64000", got)
	}
	if got := target["vision"]; got != true {
		t.Errorf("vision = %v, want true", got)
	}
	if got := target["reasoning"]; got != true {
		t.Errorf("reasoning = %v, want true", got)
	}

	// Base-only fields that were never requested must not leak in.
	for _, key := range []string{"max_input_tokens", "display_name", "description"} {
		if _, exists := target[key]; exists {
			t.Errorf("did not expect %q in OpenAI model response, got %v", key, target[key])
		}
	}
}

// TestOpenAIModelsOmitsAbsentCapabilitiesForBareModels ensures a model that
// reports no capabilities still returns the minimal base listing, so the change
// does not invent data for existing providers.
func TestOpenAIModelsOmitsAbsentCapabilitiesForBareModels(t *testing.T) {
	gin.SetMode(gin.TestMode)

	modelRegistry := registry.GetGlobalRegistry()
	clientID := "openai-plugin-bare-test"
	modelRegistry.RegisterClient(clientID, "plugin-bare", []*registry.ModelInfo{{
		ID:      "plugin-bare/model",
		Object:  "model",
		OwnedBy: "plugin-bare",
	}})
	t.Cleanup(func() {
		modelRegistry.UnregisterClient(clientID)
	})

	handler := NewOpenAIAPIHandler(handlers.NewBaseAPIHandlers(&config.SDKConfig{}, nil))

	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodGet, "/v1/models", nil)

	handler.OpenAIModels(c)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", recorder.Code, http.StatusOK, recorder.Body.String())
	}

	var resp struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode /v1/models response: %v; body=%s", err, recorder.Body.String())
	}

	var target map[string]any
	for _, m := range resp.Data {
		if id, _ := m["id"].(string); id == "plugin-bare/model" {
			target = m
			break
		}
	}
	if target == nil {
		t.Fatalf("expected plugin-bare/model in response, got %s", recorder.Body.String())
	}

	for _, key := range []string{"context_length", "vision", "reasoning", "supported_input_modalities"} {
		if _, exists := target[key]; exists {
			t.Errorf("did not expect %q for a model without capabilities, got %v", key, target[key])
		}
	}
}
