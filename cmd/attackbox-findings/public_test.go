package main

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

func TestPublicPrivacyCoverageAndReceipt(t *testing.T) {
	day := time.Date(2026, 11, 25, 0, 0, 0, 0, time.UTC)
	captures := []captureRecord{
		{Route: "/unmatched", Status: 404, Method: "GET", RemoteAddr: "1.2.3.4"},
		{Route: "/unmatched", Status: 404, Method: "GET", RemoteAddr: "1.2.3.5"},
		{Route: "SECRET<script>", Status: 200, Method: "SECRET", RemoteAddr: "1.2.3.6"},
	}
	spans := []otlpSpan{
		{Attributes: []struct {
			Key   string          `json:"key"`
			Value json.RawMessage `json:"value"`
		}{
			{Key: "attackbox.connection.outcome", Value: []byte(`{"stringValue":"tls_failed"}`)},
		}},
		{Attributes: []struct {
			Key   string          `json:"key"`
			Value json.RawMessage `json:"value"`
		}{
			{Key: "attackbox.connection.outcome", Value: []byte(`{"stringValue":"tls_failed"}`)},
		}},
		{Attributes: []struct {
			Key   string          `json:"key"`
			Value json.RawMessage `json:"value"`
		}{
			{Key: "attackbox.connection.outcome", Value: []byte(`{"stringValue":"tls_failed"}`)},
		}},
		{Attributes: []struct {
			Key   string          `json:"key"`
			Value json.RawMessage `json:"value"`
		}{
			{Key: "attackbox.connection.outcome", Value: []byte(`{"stringValue":"tls_failed"}`)},
		}},
		{Attributes: []struct {
			Key   string          `json:"key"`
			Value json.RawMessage `json:"value"`
		}{
			{Key: "attackbox.connection.outcome", Value: []byte(`{"stringValue":"SECRET"}`)},
		}},
	}
	b, err := renderPublic(captures, spans, day, day.Add(15*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{"SECRET", "<script>"} {
		if bytes.Contains(b, []byte(private)) {
			t.Fatal("untrusted label leaked")
		}
	}
	for _, want := range []string{"3 request records", "`tls_failed`: 4", "`GET` | `/unmatched` | 404 | 2", "does not retain request or response bodies", "Updated from local evidence"} {
		if !bytes.Contains(b, []byte(want)) {
			t.Fatal("missing evidence context", want)
		}
	}
}
