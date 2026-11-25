package main

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestPublicPrivacyCoverageAndReceipt(t *testing.T) {
	raw := []byte(`{"data":{"actor":{"account":{
	"total":{"results":[{"count":3,"uniqueCount.id":3}]},
	"requests":{"results":[{"count":2,"facet":["/unmatched","404","GET"]},{"count":1,"facet":["SECRET<script>","SECRET","SECRET"]}]},
	"connections":{"results":[{"count":4,"facet":"tls_failed"},{"count":1,"facet":"SECRET"}]},
	"health":{"results":[{"latest.timestamp":1795617316450,"latest.attackbox.otel_dropped_spans_total":0}]}
	}}}}`)
	day := time.Date(2026, 11, 25, 0, 0, 0, 0, time.UTC)
	b, err := renderPublic(raw, day, day.Add(15*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{"SECRET", "<script>"} {
		if bytes.Contains(b, []byte(private)) {
			t.Fatal("untrusted label leaked")
		}
	}
	for _, want := range []string{"3 distinct span IDs", "`tls_failed`: 4", "`GET` | `/unmatched` | 404 | 2", "does not retain request or response bodies", "Latest public-service heartbeat received"} {
		if !bytes.Contains(b, []byte(want)) {
			t.Fatal("missing evidence context", want)
		}
	}
	if _, err := renderPublic(bytes.Replace(raw, []byte(`"count":3`), []byte(`"count":4`), 1), day, day); err == nil {
		t.Fatal("facet truncation ignored")
	}
	if _, err := renderPublic([]byte(`{"errors":[{"message":"SECRET"}]}`), day, day); err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Fatal("unsafe GraphQL failure")
	}
	t.Setenv("NEW_RELIC_ACCOUNT_ID", "123")
	q := publicQuery(day, day.Add(15*time.Hour))
	if !strings.Contains(q, "SINCE 1795582800") || !strings.Contains(q, "public.request") {
		t.Fatal("wrong day boundary", q)
	}
}
