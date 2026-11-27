package publicedge

import (
	"crypto/rand"
	_ "embed"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
)

// gatewayPersona makes one public port answer like the server that usually listens there.
type gatewayPersona struct {
	server     string                      // Server header; "" sends none
	paths      map[string]http.HandlerFunc // exact GET paths; each path is also its http.route label
	posts      map[string]http.HandlerFunc // exact POST paths, labelled the same way
	notFound   http.HandlerFunc            // answer to an unmatched request; nil keeps the gateway's 404
	notAllowed http.HandlerFunc            // answer to a wrong method on a route family; nil keeps the gateway's 405
	needKey    bool                        // a route family answers 401 until the client sends any credential
	noKey      http.HandlerFunc            // that 401 answer; nil keeps the gateway's
	local      bool                        // a local model server: it lists and serves no hosted API names
	owner      string                      // owned_by of its /v1/models entries; "" keeps the gateway's owners
}

const gatewayJSONUTF8 = "application/json; charset=utf-8"
const gatewayHTML = "text/html; charset=utf-8"

// Persona paths must match the http.route allowlist in deploy/public-otel/config.yaml.
// The Ollama answers were compared with a real server; the other products' answers were written from their documents.
var gatewayPersonas = map[int]gatewayPersona{
	443: {needKey: true}, // hosted gateway: a client that must send a key shows which key it has
	11434: {local: true, owner: "library", // Ollama
		notFound:   gatewayFixed(404, "text/plain", "404 page not found"),
		notAllowed: gatewayFixed(405, "text/plain", "405 method not allowed"),
		paths: map[string]http.HandlerFunc{
			"/":            gatewayFixed(200, "text/plain; charset=utf-8", "Ollama is running"),
			"/api/version": gatewayFixed(200, gatewayJSONUTF8, `{"version":"`+gatewayOllamaVersion+`"}`),
			"/api/ps":      gatewayOllamaPS,
		}},
	1234: {local: true, owner: "organization_owner", paths: map[string]http.HandlerFunc{"/api/v0/models": gatewayLMStudioModels}, notFound: gatewayLMStudioNotFound},
	8000: {local: true, owner: "vllm", server: "uvicorn", notFound: gatewayFixed(404, gatewayJSON, `{"detail":"Not Found"}`), paths: map[string]http.HandlerFunc{ // vLLM
		"/health":  func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) },
		"/version": gatewayFixed(200, gatewayJSON, `{"version":"0.10.2"}`),
	}},
	8080: {local: true, owner: "llamacpp", server: "llama.cpp", notFound: gatewayFixed(404, gatewayJSONUTF8, `{"error":{"code":404,"message":"File Not Found","type":"not_found_error"}}`), paths: map[string]http.HandlerFunc{
		"/":       gatewayFixed(200, gatewayHTML, `<!DOCTYPE html><html><head><meta charset="utf-8"><title>llama.cpp - chat</title></head><body><div id="app"></div></body></html>`),
		"/health": gatewayFixed(200, gatewayJSONUTF8, `{"status":"ok"}`),
	}},
	3000: {server: "uvicorn", needKey: true, noKey: gatewayFixed(401, gatewayJSON, `{"detail":"Not authenticated"}`), // Open WebUI
		notFound: gatewayFixed(404, gatewayJSON, `{"detail":"Not Found"}`),
		paths: map[string]http.HandlerFunc{
			"/":            gatewayFixed(200, gatewayHTML, gatewayOpenWebUIPage),
			"/health":      gatewayFixed(200, gatewayJSON, `{"status":true}`),
			"/api/version": gatewayFixed(200, gatewayJSON, `{"version":"0.6.36"}`),
			// "onboarding" says that no account exists yet: the first sign-up becomes the administrator.
			"/api/config": gatewayFixed(200, gatewayJSON, `{"status":true,"name":"Open WebUI","version":"0.6.36","default_locale":"","oauth":{"providers":{}},"features":{"auth":true,"auth_trusted_header":false,"enable_signup_password_confirmation":false,"enable_ldap":false,"enable_api_key":true,"enable_signup":true,"enable_login_form":true,"enable_websocket":true,"enable_version_update_check":true},"onboarding":true}`),
			// The page shell links this icon, and scanners identify the product by its hash.
			"/static/favicon.png": gatewayFixed(200, "image/png", gatewayOpenWebUIFavicon),
		},
		posts: map[string]http.HandlerFunc{
			"/api/v1/auths/signup": gatewayOpenWebUISignup,
			"/api/v1/auths/signin": gatewayFixed(400, gatewayJSON, `{"detail":"The email or password provided is incorrect. Please check for typos and try logging in again."}`),
		}},
	4000: {server: "uvicorn", needKey: true, // LiteLLM proxy
		noKey:    gatewayFixed(401, gatewayJSON, `{"error":{"message":"Authentication Error, No api key passed in.","type":"auth_error","param":"None","code":"401"}}`),
		notFound: gatewayFixed(404, gatewayJSON, `{"detail":"Not Found"}`),
		paths: map[string]http.HandlerFunc{
			"/":                  gatewayFixed(200, gatewayHTML, gatewayLiteLLMPage),
			"/health/liveliness": gatewayFixed(200, gatewayJSON, `"I'm alive!"`),
			"/health/liveness":   gatewayFixed(200, gatewayJSON, `"I'm alive!"`),
			"/health/readiness":  gatewayFixed(200, gatewayJSON, `{"status":"healthy","db":"connected","cache":null,"litellm_version":"1.79.1","success_callbacks":[],"use_aiohttp_transport":true}`),
		}},
	8188: {server: "Python/3.12 aiohttp/3.12.15", notFound: gatewayFixed(404, "text/plain; charset=utf-8", "404: Not Found"), // ComfyUI
		paths: map[string]http.HandlerFunc{
			"/":                 gatewayFixed(200, gatewayHTML, gatewayComfyPage),
			"/system_stats":     gatewayFixed(200, gatewayJSONUTF8, gatewayComfyStats),
			"/api/system_stats": gatewayFixed(200, gatewayJSONUTF8, gatewayComfyStats),
			"/queue":            gatewayFixed(200, gatewayJSONUTF8, `{"queue_running": [], "queue_pending": []}`),
			"/api/queue":        gatewayFixed(200, gatewayJSONUTF8, `{"queue_running": [], "queue_pending": []}`),
			"/history":          gatewayFixed(200, gatewayJSONUTF8, `{}`),
			"/api/history":      gatewayFixed(200, gatewayJSONUTF8, `{}`),
			"/prompt":           gatewayFixed(200, gatewayJSONUTF8, `{"exec_info": {"queue_remaining": 0}}`),
			"/api/prompt":       gatewayFixed(200, gatewayJSONUTF8, `{"exec_info": {"queue_remaining": 0}}`),
		},
		// A queued workflow is recorded with the request; nothing runs it.
		posts: map[string]http.HandlerFunc{"/prompt": gatewayComfyQueue, "/api/prompt": gatewayComfyQueue}},
	8888: {server: "TornadoServer/6.5.2", notFound: gatewayFixed(404, gatewayJSON, `{"message": "Not Found", "reason": null}`), // Jupyter Server with a token
		paths: map[string]http.HandlerFunc{
			"/":                gatewayJupyterLogin,
			"/lab":             gatewayJupyterLogin,
			"/tree":            gatewayJupyterLogin,
			"/login":           gatewayFixed(200, gatewayHTML, gatewayJupyterPage),
			"/api":             gatewayFixed(200, gatewayJSON, `{"version": "2.17.0"}`),
			"/api/status":      gatewayJupyterForbidden,
			"/api/kernels":     gatewayJupyterForbidden,
			"/api/contents":    gatewayJupyterForbidden,
			"/api/sessions":    gatewayJupyterForbidden,
			"/api/terminals":   gatewayJupyterForbidden,
			"/api/kernelspecs": gatewayJupyterForbidden,
		},
		posts: map[string]http.HandlerFunc{"/login": gatewayFixed(401, gatewayHTML, gatewayJupyterPage)}},
}

func gatewayFixed(status int, contentType, body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) { gatewayReply(w, status, contentType, body) }
}

var gatewayJupyterForbidden = gatewayFixed(403, gatewayJSON, `{"message": "Forbidden", "reason": null}`)

// gatewayJupyterLogin sends a page request to the login form, as a server with a token does.
func gatewayJupyterLogin(w http.ResponseWriter, r *http.Request) {
	next := r.URL.Path
	if next == "/" {
		next = "/lab"
	}
	w.Header().Set("Location", "/login?next="+url.QueryEscape(next))
	gatewayReply(w, http.StatusFound, gatewayHTML, "")
}

// gatewayUUID returns a random version 4 UUID.
func gatewayUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:]) // never fails
	b[6], b[8] = b[6]&0x0f|0x40, b[8]&0x3f|0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:])
}

// gatewayOpenWebUISignup answers the first sign-up with a session token. The token is random and opens nothing;
// a client that sends it later shows as a credential of type jwt.
func gatewayOpenWebUISignup(w http.ResponseWriter, _ *http.Request) {
	id := gatewayUUID()
	enc := base64.RawURLEncoding.EncodeToString
	var sig [32]byte
	_, _ = rand.Read(sig[:])
	token := enc([]byte(`{"alg":"HS256","typ":"JWT"}`)) + "." + enc([]byte(`{"id":"`+id+`"}`)) + "." + enc(sig[:])
	gatewayReply(w, 200, gatewayJSON, `{"id":"`+id+`","name":"admin","role":"admin","profile_image_url":"/user.png","token":"`+token+`","token_type":"Bearer","expires_at":null,"permissions":{}}`)
}

func gatewayComfyQueue(w http.ResponseWriter, _ *http.Request) {
	gatewayReply(w, 200, gatewayJSONUTF8, `{"prompt_id": "`+gatewayUUID()+`", "number": 1, "node_errors": {}}`)
}

const gatewayComfyStats = `{"system": {"os": "posix", "ram_total": 134985633792, "ram_free": 118341234688, "comfyui_version": "0.3.68", "required_frontend_version": "1.28.8", "python_version": "3.12.3 (main, Aug 14 2025, 17:47:21) [GCC 13.3.0]", "pytorch_version": "2.8.0+cu128", "embedded_python": false, "argv": ["main.py", "--listen", "0.0.0.0"]}, "devices": [{"name": "cuda:0 NVIDIA RTX A6000 : cudaMallocAsync", "type": "cuda", "index": 0, "vram_total": 51041271808, "vram_free": 5368709120, "torch_vram_total": 0, "torch_vram_free": 0}]}`

// The icon of Open WebUI v0.6.36 (backend/open_webui/static/favicon.png), not changed.
// Copyright (c) 2023-2025 Timothy Jaeryang Baek (Open WebUI), Open WebUI License.
//
//go:embed openwebui_favicon.png
var gatewayOpenWebUIFavicon string

const gatewayOpenWebUIPage = `<!doctype html>
<html lang="en">
	<head>
		<meta charset="utf-8" />
		<link rel="icon" type="image/png" href="/static/favicon.png" />
		<link rel="manifest" href="/manifest.json" />
		<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, viewport-fit=cover" />
		<meta name="robots" content="noindex,nofollow" />
		<meta name="description" content="Open WebUI" />
		<title>Open WebUI</title>
	</head>
	<body data-sveltekit-preload-data="hover">
		<div style="display: contents" id="svelte-root"></div>
	</body>
</html>
`

const gatewayLiteLLMPage = `
    <!DOCTYPE html>
    <html>
    <head>
    <link type="text/css" rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css">
    <link rel="shortcut icon" href="https://fastapi.tiangolo.com/img/favicon.png">
    <title>LiteLLM API - Swagger UI</title>
    </head>
    <body>
    <div id="swagger-ui">
    </div>
    <script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
    <script>
    const ui = SwaggerUIBundle({
        url: '/openapi.json',
        dom_id: '#swagger-ui',
    })
    </script>
    </body>
    </html>
    `

const gatewayComfyPage = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>ComfyUI</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
<link rel="stylesheet" type="text/css" href="user.css" />
<link rel="stylesheet" type="text/css" href="materialdesignicons.min.css" />
</head>
<body class="litegraph grid">
<div id="vue-app"></div>
</body>
</html>
`

const gatewayJupyterPage = `<!DOCTYPE HTML>
<html>
<head>
    <meta charset="utf-8">
    <title>Jupyter Server</title>
    <link rel="shortcut icon" type="image/x-icon" href="/static/favicons/favicon.ico">
    <meta http-equiv="X-UA-Compatible" content="IE=edge" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body class="jp-ThemedContainer" dir="ltr">
<div id="site">
<div id="jupyter-main-app" class="container">
<div class="row">
<div class="navbar col-sm-8">
<div class="navbar-inner">
<div class="container">
<div class="center-nav">
<form action="/login?next=%2Flab" method="post" class="navbar-form pull-left">
<input type="hidden" name="_xsrf" value="2|5b0c1e7a|9f3d2a6c41e8b75d0c9a3f1e6b2d8a47|1795700000"/>
<label for="password_input"><strong>Password or token:</strong></label>
<input type="password" name="password" id="password_input" class="form-control">
<button type="submit" class="btn btn-default" id="login_submit">Log in</button>
</form>
</div>
</div>
</div>
</div>
</div>
</div>
</div>
</body>
</html>
`
