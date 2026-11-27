package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

func healthcheck(ctx context.Context, certPath, address string) error {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return errors.New("public certificate is unavailable")
	}
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return errors.New("public certificate is invalid")
	}
	pinned, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return errors.New("public certificate is invalid")
	}
	transport := &http.Transport{
		Proxy: nil,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true, VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 || !bytes.Equal(state.PeerCertificates[0].Raw, pinned.Raw) || time.Now().Before(pinned.NotBefore) || time.Now().After(pinned.NotAfter) {
				return errors.New("public TLS identity mismatch")
			}
			return nil
		}},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}

	for _, check := range []struct {
		method, path, body, marker string
		json                       bool
	}{
		{"GET", "/v1/models", "", `"local-instruct-8b"`, true},
		{"POST", "/v1/chat/completions", `{"model":"local-instruct-8b","messages":[{"role":"user","content":"test"}]}`, `"chatcmpl-`, true},
		{"POST", "/v1/completions", `{"model":"local-instruct-8b","prompt":"test"}`, `"cmpl-`, true},
		{"POST", "/openai/deployments/local-instruct-8b/chat/completions", `{"messages":[{"role":"user","content":"test"}]}`, `"chatcmpl-`, true},
	} {
		req, err := http.NewRequestWithContext(ctx, check.method, "https://"+address+check.path, strings.NewReader(check.body))
		if err != nil {
			return fmt.Errorf("invalid local probe: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer healthcheck") // port 443 answers 401 without a credential
		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("local HTTPS probe failed: %w", err)
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 65537))
		_ = resp.Body.Close()
		if readErr != nil || len(body) > 65536 || resp.StatusCode != http.StatusOK || !bytes.Contains(body, []byte(check.marker)) || check.json && !json.Valid(body) {
			return fmt.Errorf("unexpected local HTTPS response for %s %s", check.method, check.path)
		}
	}
	return nil
}
