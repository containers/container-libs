package copy

import (
	"maps"
	"testing"

	chunkedToc "go.podman.io/storage/pkg/chunked/toc"
)

func TestAnnotationsAfterCompressionChange(t *testing.T) {
	var chunkedKey string
	for key := range chunkedToc.ChunkedAnnotations {
		chunkedKey = key
		break
	}
	tests := []struct {
		original map[string]string
		expected map[string]string
	}{
		{nil, nil},
		{map[string]string{"org.example.content": "value"}, map[string]string{"org.example.content": "value"}},
		{map[string]string{"org.example.content": "value", chunkedKey: "stale"}, map[string]string{"org.example.content": "value"}},
	}
	for _, test := range tests {
		actual := annotationsAfterCompressionChange(test.original)
		if !maps.Equal(actual, test.expected) {
			t.Errorf("got annotations %#v, expected %#v", actual, test.expected)
		}
		if len(test.original) != 0 {
			test.original["mutation-check"] = "value"
			if _, present := actual["mutation-check"]; present {
				t.Error("returned annotations share storage with the original map")
			}
		}
	}
}
