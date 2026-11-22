#!/usr/bin/env python3
"""
Attack Box client compatibility matrix.

Tests OpenAI-compatible and Ollama-native endpoints with official clients
across models, endpoints, streaming formats, and tool calls.

Uses temporary venv for openai/ollama/httpx packages - no repo dependencies.
"""
import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.request
import urllib.error
from pathlib import Path
from typing import Any, Dict, List, Optional


class Color:
    """ANSI color codes."""
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    NC = '\033[0m'


def info(msg: str) -> None:
    print(f"{Color.BLUE}●{Color.NC} {msg}")


def success(msg: str) -> None:
    print(f"{Color.GREEN}✓{Color.NC} {msg}")


def fail(msg: str) -> None:
    print(f"{Color.RED}✗{Color.NC} {msg}", file=sys.stderr)


def skip(msg: str) -> None:
    print(f"{Color.YELLOW}○{Color.NC} {msg}")


class Stats:
    """Test statistics tracker."""
    def __init__(self):
        self.total = 0
        self.passed = 0
        self.failed = 0
        self.skipped = 0

    def report(self) -> bool:
        """Print summary and return True if all passed."""
        print()
        info("=" * 40)
        info("Client Matrix Summary")
        info("=" * 40)
        print(f"Total:   {self.total}")
        print(f"{Color.GREEN}Passed:  {self.passed}{Color.NC}")
        if self.skipped > 0:
            print(f"{Color.YELLOW}Skipped: {self.skipped}{Color.NC}")
        if self.failed > 0:
            print(f"{Color.RED}Failed:  {self.failed}{Color.NC}")
            return False
        return True


class ServerFixture:
    """Manage test server lifecycle."""
    def __init__(self, openai_port: int, ollama_port: int):
        self.openai_port = openai_port
        self.ollama_port = ollama_port
        self.process = None
        self.binary = None
        self.log_file = None

    def start(self, timeout: int = 10) -> bool:
        """Build and start test server."""
        info("Building attackbox test server...")

        # Build binary
        try:
            subprocess.run(
                ["go", "build", "-o", "/tmp/attackbox-matrix-test", "./cmd/attackbox"],
                check=True,
                capture_output=True,
                cwd=Path(__file__).parent.parent,
            )
            self.binary = "/tmp/attackbox-matrix-test"
        except subprocess.CalledProcessError as e:
            fail(f"Build failed: {e.stderr.decode()}")
            return False

        # Create log file
        self.log_file = tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix='-attackbox.log')

        # Start server
        env = os.environ.copy()
        env.update({
            "ATTACKBOX_NR_DISABLED": "true",
            "ATTACKBOX_OPENAI_ADDR": f"127.0.0.1:{self.openai_port}",
            "ATTACKBOX_VLLM_ADDR": "off",
            "ATTACKBOX_OLLAMA_ADDR": f"127.0.0.1:{self.ollama_port}",
            "ATTACKBOX_TIMING": "false",
            "ATTACKBOX_MAX_STREAM": "10s",
        })

        try:
            self.process = subprocess.Popen(
                [self.binary],
                env=env,
                stdout=self.log_file,
                stderr=subprocess.STDOUT,
            )
        except Exception as e:
            fail(f"Failed to start server: {e}")
            return False

        # Wait for ready by polling /v1/models
        health_url = f"http://127.0.0.1:{self.openai_port}/v1/models"
        for attempt in range(timeout * 10):
            try:
                with urllib.request.urlopen(health_url, timeout=1) as response:
                    if response.status == 200:
                        success("Test server started")
                        return True
            except (urllib.error.URLError, OSError):
                pass
            time.sleep(0.1)

        # Failed to start - capture logs
        fail("Test server failed to become ready")
        self.log_file.seek(0)
        logs = self.log_file.read()
        if logs:
            fail("Server logs:")
            print(logs, file=sys.stderr)
        return False

    def stop(self) -> None:
        """Stop the server."""
        if self.process:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
            self.process = None
        if self.log_file:
            self.log_file.close()
            Path(self.log_file.name).unlink(missing_ok=True)
            self.log_file = None
        if self.binary and Path(self.binary).exists():
            Path(self.binary).unlink()


class VenvRunner:
    """Run Python code in isolated venv with installed packages."""
    def __init__(self):
        self.venv_dir = None
        self.python = None

    def setup(self, packages: List[str]) -> bool:
        """Create venv and install packages."""
        self.venv_dir = tempfile.mkdtemp(prefix="attackbox-venv-")
        info(f"Creating temporary venv at {self.venv_dir}")

        try:
            # Create venv
            subprocess.run(
                [sys.executable, "-m", "venv", self.venv_dir],
                check=True,
                capture_output=True,
            )

            # Find python in venv
            if sys.platform == "win32":
                self.python = os.path.join(self.venv_dir, "Scripts", "python.exe")
            else:
                self.python = os.path.join(self.venv_dir, "bin", "python")

            # Install packages
            info(f"Installing packages: {', '.join(packages)}")
            subprocess.run(
                [self.python, "-m", "pip", "install", "--quiet"] + packages,
                check=True,
                capture_output=True,
            )
            success("Virtual environment ready")
            return True

        except subprocess.CalledProcessError as e:
            fail(f"venv setup failed: {e.stderr.decode() if e.stderr else str(e)}")
            return False

    def run(self, code: str, timeout: int = 30) -> Optional[Dict[str, Any]]:
        """Run Python code in venv, return parsed JSON result."""
        if not self.python:
            return None

        try:
            result = subprocess.run(
                [self.python, "-c", code],
                capture_output=True,
                timeout=timeout,
                text=True,
            )
            if result.returncode != 0:
                return {"error": result.stderr or result.stdout}

            # Parse JSON output
            return json.loads(result.stdout)
        except subprocess.TimeoutExpired:
            return {"error": "timeout"}
        except json.JSONDecodeError:
            return {"error": f"invalid json: {result.stdout}"}
        except Exception as e:
            return {"error": str(e)}

    def cleanup(self) -> None:
        """Remove venv."""
        if self.venv_dir and Path(self.venv_dir).exists():
            import shutil
            shutil.rmtree(self.venv_dir)


def test_openai_chat(venv: VenvRunner, base_url: str, stats: Stats) -> None:
    """Test OpenAI chat completions."""
    code = f"""
import json
from openai import OpenAI

client = OpenAI(base_url="{base_url}", api_key="test-key")

# Non-streaming
response = client.chat.completions.create(
    model="qwen3:8b",
    messages=[{{"role": "user", "content": "hello"}}],
)
result = {{"type": "chat", "content": response.choices[0].message.content}}

# Streaming
stream = client.chat.completions.create(
    model="qwen3:8b",
    messages=[{{"role": "user", "content": "hi"}}],
    stream=True,
)
chunks = [chunk.choices[0].delta.content for chunk in stream if chunk.choices and chunk.choices[0].delta.content]
result["stream_chunks"] = len(chunks)

print(json.dumps(result))
"""
    stats.total += 1
    result = venv.run(code)
    if result and "error" not in result and result.get("type") == "chat":
        stats.passed += 1
        success(f"OpenAI chat: content={result.get('content')[:30]}... chunks={result.get('stream_chunks')}")
    else:
        stats.failed += 1
        fail(f"OpenAI chat failed: {result}")


def test_openai_completions(venv: VenvRunner, base_url: str, stats: Stats) -> None:
    """Test OpenAI legacy completions."""
    code = f"""
import json
from openai import OpenAI

client = OpenAI(base_url="{base_url}", api_key="test-key")

response = client.completions.create(
    model="qwen3:8b",
    prompt="hello",
)
result = {{"type": "completion", "text": response.choices[0].text}}

print(json.dumps(result))
"""
    stats.total += 1
    result = venv.run(code)
    if result and "error" not in result and result.get("type") == "completion":
        stats.passed += 1
        success(f"OpenAI completions: text={result.get('text')[:30]}...")
    else:
        stats.failed += 1
        fail(f"OpenAI completions failed: {result}")


def test_openai_embeddings(venv: VenvRunner, base_url: str, stats: Stats) -> None:
    """Test OpenAI embeddings."""
    code = f"""
import json
from openai import OpenAI

client = OpenAI(base_url="{base_url}", api_key="test-key")

response = client.embeddings.create(
    model="qwen3:8b",
    input="test embedding",
)
result = {{"type": "embeddings", "dimensions": len(response.data[0].embedding)}}

print(json.dumps(result))
"""
    stats.total += 1
    result = venv.run(code)
    if result and "error" not in result and result.get("type") == "embeddings":
        stats.passed += 1
        success(f"OpenAI embeddings: dimensions={result.get('dimensions')}")
    else:
        stats.failed += 1
        fail(f"OpenAI embeddings failed: {result}")


def test_openai_tools(venv: VenvRunner, base_url: str, stats: Stats) -> None:
    """Test OpenAI tool calls."""
    code = f"""
import json
from openai import OpenAI

client = OpenAI(base_url="{base_url}", api_key="test-key")

tools = [{{
    "type": "function",
    "function": {{
        "name": "get_weather",
        "description": "Get weather",
        "parameters": {{
            "type": "object",
            "properties": {{"location": {{"type": "string"}}}},
            "required": ["location"],
        }},
    }},
}}]

response = client.chat.completions.create(
    model="qwen3:8b",
    messages=[{{"role": "user", "content": "weather in SF"}}],
    tools=tools,
)
result = {{"type": "tools", "has_message": bool(response.choices[0].message.content)}}

print(json.dumps(result))
"""
    stats.total += 1
    result = venv.run(code)
    if result and "error" not in result and result.get("type") == "tools":
        stats.passed += 1
        success("OpenAI tools: tool schema accepted")
    else:
        stats.failed += 1
        fail(f"OpenAI tools failed: {result}")


def test_ollama_chat(venv: VenvRunner, base_url: str, stats: Stats) -> None:
    """Test Ollama chat."""
    code = f"""
import json
import httpx

# Use httpx directly since ollama Python client may not support streaming well
response = httpx.post(
    f"{base_url}/api/chat",
    json={{"model": "qwen3:8b", "messages": [{{"role": "user", "content": "hello"}}], "stream": False}},
    timeout=10,
)
data = response.json()
result = {{"type": "ollama_chat", "has_message": "message" in data}}

# Test streaming NDJSON
stream_response = httpx.post(
    f"{base_url}/api/chat",
    json={{"model": "qwen3:8b", "messages": [{{"role": "user", "content": "hi"}}], "stream": True}},
    timeout=10,
)
lines = [l for l in stream_response.text.split("\\n") if l.strip()]
result["stream_lines"] = len(lines)

print(json.dumps(result))
"""
    stats.total += 1
    result = venv.run(code)
    if result and "error" not in result and result.get("type") == "ollama_chat":
        stats.passed += 1
        success(f"Ollama chat: has_message={result.get('has_message')} stream_lines={result.get('stream_lines')}")
    else:
        stats.failed += 1
        fail(f"Ollama chat failed: {result}")


def test_ollama_generate(venv: VenvRunner, base_url: str, stats: Stats) -> None:
    """Test Ollama generate."""
    code = f"""
import json
import httpx

response = httpx.post(
    f"{base_url}/api/generate",
    json={{"model": "qwen3:8b", "prompt": "hello", "stream": False}},
    timeout=10,
)
data = response.json()
result = {{"type": "ollama_generate", "has_response": "response" in data}}

print(json.dumps(result))
"""
    stats.total += 1
    result = venv.run(code)
    if result and "error" not in result and result.get("type") == "ollama_generate":
        stats.passed += 1
        success(f"Ollama generate: has_response={result.get('has_response')}")
    else:
        stats.failed += 1
        fail(f"Ollama generate failed: {result}")


def test_ollama_embeddings(venv: VenvRunner, base_url: str, stats: Stats) -> None:
    """Test Ollama embeddings."""
    code = f"""
import json
import httpx

response = httpx.post(
    f"{base_url}/api/embed",
    json={{"model": "qwen3:8b", "input": "test"}},
    timeout=10,
)
data = response.json()
result = {{"type": "ollama_embed", "has_embeddings": "embeddings" in data}}
if "embeddings" in data and len(data["embeddings"]) > 0:
    result["dimensions"] = len(data["embeddings"][0])

print(json.dumps(result))
"""
    stats.total += 1
    result = venv.run(code)
    if result and "error" not in result and result.get("type") == "ollama_embed":
        stats.passed += 1
        success(f"Ollama embeddings: dimensions={result.get('dimensions', 'unknown')}")
    else:
        stats.failed += 1
        fail(f"Ollama embeddings failed: {result}")


def main():
    parser = argparse.ArgumentParser(
        description="Attack Box client compatibility matrix",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Tests OpenAI-compatible and Ollama-native endpoints with official clients.
Creates temporary venv with required packages - no repo dependencies.

Examples:
  %(prog)s                    # Run full matrix with built-in test server
  %(prog)s --openai-url http://localhost:8080/v1  # Test external server
  %(prog)s --no-server        # Skip server management (must already be running)
        """,
    )
    parser.add_argument("--openai-port", type=int, default=19080, help="OpenAI test port")
    parser.add_argument("--ollama-port", type=int, default=19434, help="Ollama test port")
    parser.add_argument("--openai-url", help="External OpenAI-compatible base URL")
    parser.add_argument("--ollama-url", help="External Ollama base URL")
    parser.add_argument("--no-server", action="store_true", help="Skip server lifecycle")
    parser.add_argument("--keep-venv", action="store_true", help="Keep venv for debugging")

    args = parser.parse_args()

    stats = Stats()
    server = None
    venv = VenvRunner()

    try:
        # Determine URLs
        if args.openai_url:
            openai_base = args.openai_url
        else:
            openai_base = f"http://127.0.0.1:{args.openai_port}/v1"

        if args.ollama_url:
            ollama_base = args.ollama_url
        else:
            ollama_base = f"http://127.0.0.1:{args.ollama_port}"

        # Start server if needed
        if not args.no_server and not (args.openai_url and args.ollama_url):
            server = ServerFixture(args.openai_port, args.ollama_port)
            if not server.start():
                return 1

        # Setup venv
        if not venv.setup(["openai", "httpx"]):
            return 1

        print()
        info("=" * 40)
        info("OpenAI-compatible endpoints")
        info("=" * 40)
        test_openai_chat(venv, openai_base, stats)
        test_openai_completions(venv, openai_base, stats)
        test_openai_embeddings(venv, openai_base, stats)
        test_openai_tools(venv, openai_base, stats)

        print()
        info("=" * 40)
        info("Ollama-native endpoints")
        info("=" * 40)
        test_ollama_chat(venv, ollama_base, stats)
        test_ollama_generate(venv, ollama_base, stats)
        test_ollama_embeddings(venv, ollama_base, stats)

        # Report
        passed = stats.report()
        return 0 if passed else 1

    finally:
        if server:
            server.stop()
        if not args.keep_venv:
            venv.cleanup()
        else:
            info(f"venv kept at {venv.venv_dir}")


if __name__ == "__main__":
    sys.exit(main())
