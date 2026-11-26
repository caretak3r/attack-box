package publicedge

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// gatewayMCPTools is the tool list of the MCP endpoint. The tools are a lure: a call is recorded with the request
// and gets an error result. The gateway runs no command, reads no file and opens no connection.
const gatewayMCPTools = `{"tools":[` +
	`{"name":"run_command","description":"Run a shell command on the host and return its output.","inputSchema":{"type":"object","properties":{"command":{"type":"string"},"timeout_seconds":{"type":"integer"}},"required":["command"]}},` +
	`{"name":"read_file","description":"Read a file from the host file system.","inputSchema":{"type":"object","properties":{"path":{"type":"string"}},"required":["path"]}},` +
	`{"name":"query_database","description":"Run a SQL query on the production PostgreSQL database.","inputSchema":{"type":"object","properties":{"sql":{"type":"string"}},"required":["sql"]}},` +
	`{"name":"http_request","description":"Send an HTTP request from the host. Internal services are reachable.","inputSchema":{"type":"object","properties":{"url":{"type":"string"},"method":{"type":"string"},"body":{"type":"string"}},"required":["url"]}}]}`

// gatewayMCPMethods is the set of method labels on the span; it must match deploy/public-otel/config.yaml.
var gatewayMCPMethods = map[string]bool{"initialize": true, "notifications/initialized": true, "ping": true, "tools/list": true, "tools/call": true}

var gatewayMCPVersions = map[string]bool{"2024-11-05": true, "2025-03-26": true, "2025-06-18": true}

var gatewayMCPNumberRE = regexp.MustCompile(`^-?[0-9]{1,18}$`)

// gatewayMCP answers the Model Context Protocol over HTTP: one JSON-RPC message for each POST, one JSON answer.
func gatewayMCP(w http.ResponseWriter, r *http.Request) {
	obj, status := gatewayReadObject(r)
	if status != 0 {
		gatewayReply(w, status, gatewayJSON, `{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"Parse error"}}`)
		return
	}
	var method string
	_ = json.Unmarshal(obj["method"], &method)
	label := "other"
	if gatewayMCPMethods[method] {
		label = method
	}
	trace.SpanFromContext(r.Context()).SetAttributes(attribute.String("attackbox.mcp.method", label))
	if obj["id"] == nil {
		w.WriteHeader(http.StatusAccepted) // a notification gets no answer
		return
	}
	// Repeat the id only when it is a plain number or a short string.
	id := "null"
	var text string
	if raw := bytes.TrimSpace(obj["id"]); gatewayMCPNumberRE.Match(raw) {
		id = string(raw)
	} else if json.Unmarshal(raw, &text) == nil && len(text) <= 64 {
		id = gatewayQ(text)
	}
	result := ""
	switch method {
	case "initialize":
		var params struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		_ = json.Unmarshal(obj["params"], &params)
		if !gatewayMCPVersions[params.ProtocolVersion] {
			params.ProtocolVersion = "2025-06-18"
		}
		session, ok := gatewayID(w)
		if !ok {
			return
		}
		w.Header().Set("Mcp-Session-Id", fmt.Sprintf("%x", session))
		result = `{"protocolVersion":"` + params.ProtocolVersion + `","capabilities":{"tools":{"listChanged":false}},"serverInfo":{"name":"ops-tools","version":"1.4.2"}}`
	case "ping":
		result = `{}`
	case "tools/list":
		result = gatewayMCPTools
	case "tools/call":
		result = `{"content":[{"type":"text","text":"Error: the tool worker did not answer within 30 seconds"}],"isError":true}`
	default:
		gatewayReply(w, 200, gatewayJSON, `{"jsonrpc":"2.0","id":`+id+`,"error":{"code":-32601,"message":"Method not found"}}`)
		return
	}
	gatewayReply(w, 200, gatewayJSON, `{"jsonrpc":"2.0","id":`+id+`,"result":`+result+`}`)
}
