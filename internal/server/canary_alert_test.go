package server

import (
	"testing"

	"attackbox/internal/responder"
)

func TestCanaryAlertRequiresCredentialPresentation(t *testing.T) {
	for _, tc := range []struct {
		probe, key, value string
		want              int
	}{
		{"canary-reuse", "two_part", "present_in_history", 0},
		{"canary-reuse", "two_part", "presented_undelivered", 0},
		{"canary-reuse", "two_part", "newly_echoed,destination_placed", 0},
		{"canary-reuse", "two_part", "credential_presented", 1},
		{"canary-reuse", "two_part", "credential_presented,newly_echoed", 1},
		{"canary-reuse", "credential_source", "credential_presented", 0},
		{"canary-reuse", "independently_observed", "credential_presented", 0},
		{"canary-reuse", "unrecognized_field", "credential_presented", 0},
		{"other", "two_part", "credential_presented", 0},
		{"canary-reuse", "two_part", "not_credential_presented", 0},
	} {
		t.Run(tc.probe+"/"+tc.key+"/"+tc.value, func(t *testing.T) {
			obs := []responder.Observation{{ProbeID: "canary-reuse", Result: map[string]string{"other": "present_in_history"}}, {ProbeID: tc.probe, Result: map[string]string{tc.key: tc.value}}}
			if got := canaryCredentialPresented(obs); got != tc.want {
				t.Fatalf("got %d want %d", got, tc.want)
			}
		})
	}
}
