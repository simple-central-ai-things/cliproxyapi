package registry

import "testing"

// TestConvertModelToMapOpenAIExposesCapabilities checks that the OpenAI model
// listing carries the capability fields that a provider plugin reported via its
// ModelInfo: context window, modalities, and the derived vision/reasoning
// markers. These are the fields the /v1/models handler must not drop.
func TestConvertModelToMapOpenAIExposesCapabilities(t *testing.T) {
	r := newTestModelRegistry()
	r.RegisterClient("cap-client", "plugin-cap", []*ModelInfo{{
		ID:                        "plugin-cap/model",
		Object:                    "model",
		OwnedBy:                   "plugin-cap",
		Type:                      "openai",
		ContextLength:             262144,
		MaxContextLength:          1048576,
		MaxCompletionTokens:       64000,
		SupportedParameters:       []string{"temperature"},
		SupportedInputModalities:  []string{"text", "image"},
		SupportedOutputModalities: []string{"text"},
		Thinking:                  &ThinkingSupport{Levels: []string{"low", "high"}},
	}})

	models := r.GetAvailableModels("openai")
	byID := make(map[string]map[string]any, len(models))
	for _, m := range models {
		id, _ := m["id"].(string)
		byID[id] = m
	}

	got, ok := byID["plugin-cap/model"]
	if !ok {
		t.Fatalf("expected plugin-cap/model in openai model list, got %v", byID)
	}

	intValue := func(key string) (int, bool) {
		switch v := got[key].(type) {
		case int:
			return v, true
		case int64:
			return int(v), true
		}
		return 0, false
	}

	if v, ok := intValue("context_length"); !ok || v != 262144 {
		t.Errorf("context_length = %v, want 262144", got["context_length"])
	}
	if v, ok := intValue("max_context_length"); !ok || v != 1048576 {
		t.Errorf("max_context_length = %v, want 1048576", got["max_context_length"])
	}
	if v, ok := intValue("max_completion_tokens"); !ok || v != 64000 {
		t.Errorf("max_completion_tokens = %v, want 64000", got["max_completion_tokens"])
	}
	if v, ok := got["vision"].(bool); !ok || !v {
		t.Errorf("vision = %v, want true (image input modality)", got["vision"])
	}
	if v, ok := got["reasoning"].(bool); !ok || !v {
		t.Errorf("reasoning = %v, want true (Thinking set)", got["reasoning"])
	}
	if v, ok := got["supported_input_modalities"].([]string); !ok || len(v) != 2 {
		t.Errorf("supported_input_modalities = %v, want [text image]", got["supported_input_modalities"])
	}
	if v, ok := got["supported_output_modalities"].([]string); !ok || len(v) != 1 {
		t.Errorf("supported_output_modalities = %v, want [text]", got["supported_output_modalities"])
	}
}

// TestConvertModelToMapOpenAIOmitsAbsentCapabilities ensures capability fields
// are only emitted when the model actually declares them, so the listing never
// invents data.
func TestConvertModelToMapOpenAIOmitsAbsentCapabilities(t *testing.T) {
	r := newTestModelRegistry()
	r.RegisterClient("plain-client", "plugin-plain", []*ModelInfo{{
		ID:      "plugin-plain/model",
		Object:  "model",
		OwnedBy: "plugin-plain",
	}})

	models := r.GetAvailableModels("openai")
	byID := make(map[string]map[string]any, len(models))
	for _, m := range models {
		id, _ := m["id"].(string)
		byID[id] = m
	}

	got, ok := byID["plugin-plain/model"]
	if !ok {
		t.Fatalf("expected plugin-plain/model in openai model list, got %v", byID)
	}

	for _, key := range []string{
		"context_length",
		"max_context_length",
		"max_completion_tokens",
		"vision",
		"reasoning",
		"supported_input_modalities",
		"supported_output_modalities",
	} {
		if _, exists := got[key]; exists {
			t.Errorf("expected %q to be omitted for a model without capabilities, got %v", key, got[key])
		}
	}
}
