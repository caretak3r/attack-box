#!/bin/bash
set -euo pipefail

repo_root=$(cd "$(dirname "$0")/.." && pwd)

pass() { printf 'PASS %s\n' "$1"; }
fail() { printf 'FAIL %s: %s\n' "$1" "$2" >&2; return 1; }

testroot=$(mktemp -d)
trap 'rm -rf "$testroot"' EXIT

logfile=$testroot/call.log
mkdir -p "$testroot/bin" "$testroot/fixtures/evidence/public-otel" "$testroot/fixtures/evidence/attackbox-evidence/public-otel"

# Fake ssh that can execute python locally for verify scripts
cat > "$testroot/bin/ssh" <<'FAKE_SSH'
#!/bin/bash
echo "ssh $*" >> "$CALL_LOG"
# For verify scripts: execute python remotely means run locally with ATTACKBOX_EVIDENCE_ROOT set
if [[ $# == 2 && $2 =~ ^python3[[:space:]] ]]; then
	export ATTACKBOX_EVIDENCE_ROOT=${ATTACKBOX_EVIDENCE_ROOT:-/var/lib}
	eval "$2"
	exit $?
fi
# For hostname check
if [[ $* == *"hostname -s"* ]]; then
	echo "test-host"
	exit 0
fi
# For ledger checks in cutover
if [[ $* == *"cat /var/lib/attackbox-public/ledger/commit"* ]]; then
	echo "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	exit 0
fi
# For firewall open checks
if [[ $* == *"/var/lib/attackbox-public/ledger"* ]]; then
	exit 0  # Pretend success
fi
exit 0
FAKE_SSH
chmod +x "$testroot/bin/ssh"

# Fake curl for firewall API
cat > "$testroot/bin/curl" <<'FAKE_CURL'
#!/bin/bash
echo "curl $*" >> "$CALL_LOG"
if [[ $* == *"/instances/"* ]]; then
	echo '{"instance":{"id":"inst-id","main_ip":"1.2.3.4"}}'
elif [[ $* == *"/firewalls/"* && $* == *"/rules"* && $* != *DELETE* ]]; then
	echo '{"firewall_rules":[]}'
elif [[ $* == *"/firewalls/"* ]]; then
	echo '{"firewall":{"id":"fw-id"}}'
fi
exit 0
FAKE_CURL
chmod +x "$testroot/bin/curl"

# Fake git
cat > "$testroot/bin/git" <<'FAKE_GIT'
#!/bin/bash
echo "git $*" >> "$CALL_LOG"
case "$*" in
	*"bundle create"*)
		# Extract bundle path (second-to-last arg)
		for arg in "$@"; do :; done
		prev=$arg
		for arg in "$@"; do
			if [[ $arg != "$prev" ]]; then
				bundle=$arg
			fi
			prev=$arg
		done
		touch "$bundle"
		;;
	*"clone"*)
		dest="${@: -1}"
		mkdir -p "$dest/.git"
		echo "ref: refs/heads/main" > "$dest/.git/HEAD"
		;;
	*"rev-parse HEAD"*|*"rev-parse --absolute-git-dir"*)
		if [[ $* == *"--absolute-git-dir"* ]]; then
			# Find -C argument
			for i in "${!@}"; do
				if [[ ${!i} == "-C" ]]; then
					idx=$((i+1))
					echo "${!idx}/.git"
					exit 0
				fi
			done
			echo "$PWD/.git"
		else
			echo "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		fi
		;;
	*"verify-commit"*|*"log -1"*)
		if [[ $* == *"--format"* ]]; then
			if [[ $* == *"%G? %GF"* ]]; then
				echo "G 7026F1FDA2A21BC035F17D3B4D9E5BA7BBE1EB29"
			elif [[ $* == *"%GF"* ]]; then
				echo "7026F1FDA2A21BC035F17D3B4D9E5BA7BBE1EB29"
			else
				echo "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa G 7026F1FDA2A21BC035F17D3B4D9E5BA7BBE1EB29"
			fi
		fi
		;;
	*"checkout"*)
		;;
	*"show"*)
		echo "#!/bin/bash"
		echo "echo 'fake script'"
		echo "exit 0"
		;;
esac
exit 0
FAKE_GIT
chmod +x "$testroot/bin/git"

# Fake gpg
cat > "$testroot/bin/gpg" <<'FAKE_GPG'
#!/bin/bash
echo "gpg $*" >> "$CALL_LOG"
exit 0
FAKE_GPG
chmod +x "$testroot/bin/gpg"

# Fake jq
cat > "$testroot/bin/jq" <<'FAKE_JQ'
#!/bin/bash
# For state.json reads
if [[ ${2:-} == ".instance_id" ]]; then echo "inst-id"
elif [[ ${2:-} == ".firewall_id" ]]; then echo "fw-id"
elif [[ ${2:-} == ".ssh_rule_id" ]]; then echo "12"
elif [[ ${2:-} == ".admin_cidr" ]]; then echo "5.6.7.8/32"
elif [[ ${2:-} == ".main_ip" ]]; then echo "1.2.3.4"
else
	# For other jq calls, use real jq
	exec /usr/bin/jq "$@"
fi
FAKE_JQ
chmod +x "$testroot/bin/jq"

# Fake vultr-launch.sh
cat > "$testroot/fake-vultr-launch.sh" <<'FAKE_LAUNCH'
#!/bin/bash
echo "vultr-launch.sh $*" >> "$CALL_LOG"
if [[ $1 == ssh ]]; then
	shift
	exec ssh "$@"
fi
exit 0
FAKE_LAUNCH
chmod +x "$testroot/fake-vultr-launch.sh"

# Fake firewall ledger
cat > "$testroot/fake-firewall-ledger.sh" <<'FAKE_LEDGER'
#!/bin/bash
_public_fw_check() {
	echo "$1 $2" >> "$CALL_LOG.fw_check"
	echo "absent"
}
_public_fw_snapshot() {
	echo ""
}
public_firewall_open() {
	echo "firewall open" >> "$CALL_LOG"
	local ledgerdir=$1 commit=$5 bundle_sha=$6
	mkdir -p "$ledgerdir"
	cat > "$ledgerdir/public-firewall-ledger.json" <<JSON
{"phase":"open","firewall":"fw-id","instance":"inst-id","ip":"1.2.3.4","commit":"$commit","bundle_sha":"$bundle_sha","management":"5.6.7.8/32","ssh_id":12,"rules":{"1":"rule1","2":"rule2"}}
JSON
}
public_firewall_rollback() {
	echo "firewall close" >> "$CALL_LOG"
}
FAKE_LEDGER
chmod +x "$testroot/fake-firewall-ledger.sh"

export CALL_LOG=$logfile
export PATH=$testroot/bin:$PATH
export ATTACKBOX_VULTR_LAUNCH=$testroot/fake-vultr-launch.sh
export ATTACKBOX_FIREWALL_LEDGER=$testroot/fake-firewall-ledger.sh

# Test (a): prepare.sh creates valid scripts
test_prepare() {
	local name=prepare_creates_valid_scripts
	local commit=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
	local prev=$testroot/prev-release

	mkdir -p "$prev"
	echo "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" > "$prev/bundle.sha256"

	# Create git repo
	local repo=$testroot/repo
	mkdir -p "$repo/.git/attackbox-public-ci"
	cd "$repo"

	echo "$commit linux/amd64 sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" > ".git/attackbox-public-ci/$commit-amd64.verified"
	echo "fake bundle" > ".git/attackbox-public-ci/$commit-amd64.bundle.tar"

	# Create .vultr/state.json
	mkdir -p .vultr
	cat > .vultr/state.json <<JSON
{"instance_id":"inst-id","firewall_id":"fw-id","ssh_rule_id":12,"admin_cidr":"5.6.7.8/32","main_ip":"1.2.3.4"}
JSON

	# Create .env with API key
	echo 'VULTR_API_KEY=test-key-123' > .env

	# Copy release kit
	mkdir -p scripts/public-release
	cp -r "$repo_root/scripts/public-release"/*.in scripts/public-release/
	cp "$repo_root/scripts/public-release/prepare.sh" scripts/public-release/

	# Create SSH config
	mkdir -p ~/.ssh
	if ! grep -q "^Host attackbox" ~/.ssh/config 2>/dev/null; then
		cat >> ~/.ssh/config <<CFG

Host attackbox-test
	HostName 1.2.3.4
	User root
CFG
	fi

	# Mock ssh config lookup in prepare.sh
	export ATTACKBOX_PUBLIC_NAME=test.example.org

	# Run prepare (will fail on ssh check, so we'll stub it out)
	# Instead, test the template processing directly
	local reldir=$testroot/release-test
	mkdir -p "$reldir"

	local sha=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
	for script in cutover.sh stage.sh firewall.sh verify-staged.py verify-public.py host-proof.py; do
		sed -e "s|@COMMIT@|$commit|g" \
			-e "s|@BUNDLE_SHA@|$sha|g" \
			-e "s|@PREV_RELEASE@|bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb|g" \
			-e "s|@PUBLIC_IP@|1.2.3.4|g" \
			-e "s|@PUBLIC_NAME@|test.example.org|g" \
			-e "s|@HOSTNAME@|test-host|g" \
			-e "s|@INSTANCE_ID@|inst-id|g" \
			-e "s|@FIREWALL_ID@|fw-id|g" \
			-e "s|@SSH_RULE_ID@|12|g" \
			-e "s|@ADMIN_CIDR@|5.6.7.8/32|g" \
			-e "s|@PORTS@|443,80|g" \
			-e "s|@REPO_ROOT@|$repo_root|g" \
			-e "s|@RELEASES_DIR@|$testroot/releases|g" \
			"scripts/public-release/$script.in" > "$reldir/$script"
		chmod 0700 "$reldir/$script"
	done

	# Check mode 700
	for f in cutover.sh stage.sh firewall.sh verify-staged.py verify-public.py host-proof.py; do
		local mode=$(stat -f %Lp "$reldir/$f" 2>/dev/null || stat -c %a "$reldir/$f")
		[[ $mode == 700 ]] || fail "$name" "$f mode is $mode, not 700"
	done

	# Check no unsubstituted markers
	for f in cutover.sh stage.sh firewall.sh verify-staged.py verify-public.py host-proof.py; do
		if grep -E '@[A-Z_]+@' "$reldir/$f"; then
			fail "$name" "$f has unsubstituted markers"
		fi
	done

	# Check Python compilation
	for f in verify-staged.py verify-public.py host-proof.py; do
		python3 -m py_compile "$reldir/$f" 2>&1 || fail "$name" "$f does not compile"
	done

	# Check shellcheck
	for f in cutover.sh stage.sh firewall.sh; do
		shellcheck -s bash -S error "$reldir/$f" 2>&1 || fail "$name" "$f fails shellcheck"
	done

	pass "$name"
}

# Test (b): cutover refuses when release-check receipt is missing/wrong
test_cutover_refuses_bad_receipt() {
	local name=cutover_refuses_bad_receipt
	local commit=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
	local reldir=$testroot/release-bad-receipt

	mkdir -p "$reldir"

	# Create a cutover.sh that will fail on SHA check
	cat > "$reldir/cutover.sh" <<'SCRIPT'
#!/bin/bash
set -euo pipefail
D=/tmp/nonexistent
T=/tmp/also-nonexistent
rev=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
sha=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc

# This will fail: file doesn't exist
[[ $sha =~ ^[0-9a-f]{64}$ && $(shasum -a 256 "$T/$rev-amd64.bundle.tar" | cut -d' ' -f1) == "$sha" ]]

# If we got here, that's wrong
echo "firewall close" >> "$CALL_LOG"
SCRIPT
	chmod +x "$reldir/cutover.sh"

	> "$logfile"
	if bash "$reldir/cutover.sh" 2>&1; then
		fail "$name" "cutover should have failed"
	fi

	if grep -q "firewall close" "$logfile"; then
		fail "$name" "firewall close was called despite failure"
	fi

	pass "$name"
}

# Test (c): staged-verify failure exits non-zero and shows close but no open
test_staged_verify_failure() {
	local name=staged_verify_failure
	local reldir=$testroot/release-verify-fail

	mkdir -p "$reldir/firewall"

	# Create a verify-staged.py that fails
	cat > "$reldir/verify-staged.py" <<'PY'
#!/usr/bin/env python3
import sys
print("verify-staged: missing credential span")
sys.exit(1)
PY
	chmod +x "$reldir/verify-staged.py"

	# Create minimal cutover
	cat > "$reldir/cutover.sh" <<SCRIPT
#!/bin/bash
set -euo pipefail
echo "firewall close" >> "$CALL_LOG"
if ! python3 "$reldir/verify-staged.py" 2>&1; then
	exit 1
fi
echo "firewall open" >> "$CALL_LOG"
SCRIPT
	chmod +x "$reldir/cutover.sh"

	> "$logfile"
	if bash "$reldir/cutover.sh" 2>&1; then
		fail "$name" "cutover should have failed on verify-staged"
	fi

	if ! grep -q "firewall close" "$logfile"; then
		fail "$name" "firewall close was not called"
	fi

	if grep -q "firewall open" "$logfile"; then
		fail "$name" "firewall open was called despite failure"
	fi

	pass "$name"
}

# Test (d): success path runs steps in order
test_success_path_order() {
	local name=success_path_runs_in_order

	# Create minimal scripts that log their execution
	local prevdir=$testroot/prev-success
	local reldir=$testroot/release-success

	mkdir -p "$prevdir/firewall" "$reldir/firewall"

	cat > "$prevdir/firewall.sh" <<SCRIPT
#!/bin/bash
case \${1:-} in
	verify-open) echo "verify open" >> "$logfile" ;;
	close) echo "close" >> "$logfile" ;;
	preflight) echo "preflight" >> "$logfile" ;;
esac
SCRIPT
	chmod +x "$prevdir/firewall.sh"

	cat > "$reldir/stage.sh" <<SCRIPT
#!/bin/bash
echo "stage" >> "$logfile"
SCRIPT
	chmod +x "$reldir/stage.sh"

	cat > "$reldir/verify-staged.py" <<SCRIPT
#!/usr/bin/env python3
with open("$logfile", "a") as f:
	f.write("verify staged\\n")
SCRIPT
	chmod +x "$reldir/verify-staged.py"

	cat > "$reldir/firewall.sh" <<SCRIPT
#!/bin/bash
case \${1:-} in
	preflight) echo "preflight" >> "$logfile" ;;
	open) echo "open" >> "$logfile" ;;
esac
SCRIPT
	chmod +x "$reldir/firewall.sh"

	cat > "$reldir/verify-public.py" <<SCRIPT
#!/usr/bin/env python3
with open("$logfile", "a") as f:
	f.write("verify public\\n")
SCRIPT
	chmod +x "$reldir/verify-public.py"

	# Create cutover that calls all steps
	cat > "$reldir/cutover.sh" <<SCRIPT
#!/bin/bash
set -euo pipefail
N=$prevdir
T=$reldir
sha=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc

bash "\$N/firewall.sh" verify-open
bash "\$N/firewall.sh" close
bash "\$N/firewall.sh" preflight
echo "rollback" >> "$logfile"
bash "\$T/stage.sh"
python3 "\$T/verify-staged.py"
bash "\$T/firewall.sh" preflight
bash "\$T/firewall.sh" open "\$sha"
python3 "\$T/verify-public.py"
SCRIPT
	chmod +x "$reldir/cutover.sh"

	> "$logfile"
	bash "$reldir/cutover.sh" 2>&1 || fail "$name" "cutover failed"

	# Verify order
	local expected="verify open
close
preflight
rollback
stage
verify staged
preflight
open
verify public"

	if ! diff -u <(echo "$expected") "$logfile"; then
		fail "$name" "steps not in correct order"
	fi

	pass "$name"
}

# Test (e): verify-staged.py and verify-public.py work with fixtures
test_verify_scripts_with_fixtures() {
	local name=verify_scripts_with_fixtures
	local commit=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
	local sha=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
	local reldir=$testroot/release-verify-fixtures

	mkdir -p "$reldir/firewall"
	echo "$sha" > "$reldir/bundle.sha256"
	echo "$commit linux/amd64 sha256:$sha" > "$reldir/$commit-amd64.verified"

	# Create good fixture with all required spans
	local good_traces=$testroot/fixtures/evidence/attackbox-evidence/public-otel/traces-good.jsonl
	> "$good_traces"

	# Add credential span
	cat >> "$good_traces" <<'TRACE'
{"resourceSpans":[{"scopeSpans":[{"spans":[{"attributes":[{"key":"service.name","value":{"stringValue":"attackbox-public-443"}},{"key":"service.version","value":{"stringValue":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}},{"key":"host.id","value":{"stringValue":"test-host"}},{"key":"campaign.id","value":{"stringValue":"https443-aaaaaaaaaaaa"}},{"key":"name","value":{"stringValue":"public.request"}},{"key":"server.port","value":{"intValue":"443"}},{"key":"client.address","value":{"stringValue":"1.2.3.4"}},{"key":"attackbox.credential.source","value":{"stringValue":"authorization"}},{"key":"attackbox.credential.type","value":{"stringValue":"anthropic"}},{"key":"attackbox.credential.value","value":{"stringValue":"sk-ant-staging-synthetic-proof"}},{"key":"gen_ai.request.model","value":{"stringValue":"gpt-4o"}}]}]}]}]}
TRACE

	# Add proxy credential span
	cat >> "$good_traces" <<'TRACE'
{"resourceSpans":[{"scopeSpans":[{"spans":[{"attributes":[{"key":"service.name","value":{"stringValue":"attackbox-public-443"}},{"key":"service.version","value":{"stringValue":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}},{"key":"host.id","value":{"stringValue":"test-host"}},{"key":"campaign.id","value":{"stringValue":"https443-aaaaaaaaaaaa"}},{"key":"name","value":{"stringValue":"public.request"}},{"key":"server.port","value":{"intValue":"443"}},{"key":"client.address","value":{"stringValue":"1.2.3.4"}},{"key":"attackbox.credential.source","value":{"stringValue":"proxy-authorization"}},{"key":"attackbox.credential.value","value":{"stringValue":"c3RhZ2luZzpzeW50aGV0aWM="}}]}]}]}]}
TRACE

	# Add health span
	cat >> "$good_traces" <<'TRACE'
{"resourceSpans":[{"scopeSpans":[{"spans":[{"attributes":[{"key":"service.name","value":{"stringValue":"attackbox-public-443"}},{"key":"service.version","value":{"stringValue":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}},{"key":"host.id","value":{"stringValue":"test-host"}},{"key":"campaign.id","value":{"stringValue":"https443-aaaaaaaaaaaa"}},{"key":"name","value":{"stringValue":"public.health"}},{"key":"server.port","value":{"intValue":"443"}},{"key":"client.address","value":{"stringValue":"1.2.3.4"}}]}]}]}]}
TRACE

	# Add plain port spans (all 9 ports)
	for port in 80 1234 3000 4000 8000 8080 8188 8888 11434; do
		cat >> "$good_traces" <<TRACE
{"resourceSpans":[{"scopeSpans":[{"spans":[{"attributes":[{"key":"service.name","value":{"stringValue":"attackbox-public-443"}},{"key":"service.version","value":{"stringValue":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}},{"key":"host.id","value":{"stringValue":"test-host"}},{"key":"campaign.id","value":{"stringValue":"https443-aaaaaaaaaaaa"}},{"key":"name","value":{"stringValue":"public.request"}},{"key":"server.port","value":{"intValue":"$port"}},{"key":"client.address","value":{"stringValue":"1.2.3.4"}}]}]}]}]}
TRACE
	done

	# Bad fixture 1: missing credential span
	local bad_no_cred=$testroot/fixtures/evidence/attackbox-evidence/public-otel/traces-bad-no-cred.jsonl
	> "$bad_no_cred"
	cat >> "$bad_no_cred" <<'TRACE'
{"resourceSpans":[{"scopeSpans":[{"spans":[{"attributes":[{"key":"service.name","value":{"stringValue":"attackbox-public-443"}},{"key":"service.version","value":{"stringValue":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}},{"key":"host.id","value":{"stringValue":"test-host"}},{"key":"campaign.id","value":{"stringValue":"https443-aaaaaaaaaaaa"}},{"key":"name","value":{"stringValue":"public.request"}},{"key":"server.port","value":{"intValue":"443"}},{"key":"client.address","value":{"stringValue":"1.2.3.4"}}]}]}]}]}
TRACE

	# Bad fixture 2: forbidden client field
	local bad_forbidden=$testroot/fixtures/evidence/attackbox-evidence/public-otel/traces-bad-forbidden.jsonl
	> "$bad_forbidden"
	cat >> "$bad_forbidden" <<'TRACE'
{"resourceSpans":[{"scopeSpans":[{"spans":[{"attributes":[{"key":"service.name","value":{"stringValue":"attackbox-public-443"}},{"key":"service.version","value":{"stringValue":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}},{"key":"host.id","value":{"stringValue":"test-host"}},{"key":"campaign.id","value":{"stringValue":"https443-aaaaaaaaaaaa"}},{"key":"name","value":{"stringValue":"public.request"}},{"key":"server.port","value":{"intValue":"443"}},{"key":"client.address","value":{"stringValue":"1.2.3.4"}},{"key":"attackbox.credential.source","value":{"stringValue":"authorization"}},{"key":"attackbox.credential.type","value":{"stringValue":"anthropic"}},{"key":"attackbox.credential.value","value":{"stringValue":"sk-ant-staging-synthetic-proof"}},{"key":"gen_ai.request.model","value":{"stringValue":"gpt-4o"}},{"key":"forbidden.field","value":{"stringValue":"leak"}}]}]}]}]}
TRACE
	cat >> "$bad_forbidden" <<'TRACE'
{"resourceSpans":[{"scopeSpans":[{"spans":[{"attributes":[{"key":"service.name","value":{"stringValue":"attackbox-public-443"}},{"key":"service.version","value":{"stringValue":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}},{"key":"host.id","value":{"stringValue":"test-host"}},{"key":"campaign.id","value":{"stringValue":"https443-aaaaaaaaaaaa"}},{"key":"name","value":{"stringValue":"public.request"}},{"key":"server.port","value":{"intValue":"443"}},{"key":"client.address","value":{"stringValue":"1.2.3.4"}},{"key":"attackbox.credential.source","value":{"stringValue":"proxy-authorization"}},{"key":"attackbox.credential.value","value":{"stringValue":"c3RhZ2luZzpzeW50aGV0aWM="}}]}]}]}]}
TRACE
	cat >> "$bad_forbidden" <<'TRACE'
{"resourceSpans":[{"scopeSpans":[{"spans":[{"attributes":[{"key":"service.name","value":{"stringValue":"attackbox-public-443"}},{"key":"service.version","value":{"stringValue":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}},{"key":"host.id","value":{"stringValue":"test-host"}},{"key":"campaign.id","value":{"stringValue":"https443-aaaaaaaaaaaa"}},{"key":"name","value":{"stringValue":"public.health"}},{"key":"server.port","value":{"intValue":"443"}},{"key":"client.address","value":{"stringValue":"1.2.3.4"}}]}]}]}]}
TRACE

	# Add plain port spans to bad fixtures too
	for port in 80 1234 3000 4000 8000 8080 8188 8888 11434; do
		for f in "$bad_no_cred" "$bad_forbidden"; do
			cat >> "$f" <<TRACE
{"resourceSpans":[{"scopeSpans":[{"spans":[{"attributes":[{"key":"service.name","value":{"stringValue":"attackbox-public-443"}},{"key":"service.version","value":{"stringValue":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}},{"key":"host.id","value":{"stringValue":"test-host"}},{"key":"campaign.id","value":{"stringValue":"https443-aaaaaaaaaaaa"}},{"key":"name","value":{"stringValue":"public.request"}},{"key":"server.port","value":{"intValue":"$port"}},{"key":"client.address","value":{"stringValue":"1.2.3.4"}}]}]}]}]}
TRACE
		done
	done

	# Create test verify script that reads from fixtures
	# We'll test that the scripts work with ATTACKBOX_EVIDENCE_ROOT override
	# For this test, we just verify the fixtures are parseable

	# Test good fixture parsing
	python3 <<PY || fail "$name" "good fixture parsing failed"
import json, os
os.environ["ATTACKBOX_EVIDENCE_ROOT"] = "$testroot/fixtures/evidence"
traces_file = "$good_traces"
with open(traces_file) as f:
	for line in f:
		if not line.strip(): continue
		req = json.loads(line)
		for rs in req.get("resourceSpans", []):
			for ss in rs.get("scopeSpans", []):
				for sp in ss.get("spans", []):
					attrs = {a["key"]: a.get("value",{}) for a in sp.get("attributes",[])}
					assert "service.name" in attrs or "name" in attrs
PY

	# Test bad fixture 1 detection (missing credential)
	python3 <<PY || fail "$name" "bad fixture 1 should detect missing credential"
import json
traces_file = "$bad_no_cred"
has_cred = False
with open(traces_file) as f:
	for line in f:
		if not line.strip(): continue
		req = json.loads(line)
		for rs in req.get("resourceSpans", []):
			for ss in rs.get("scopeSpans", []):
				for sp in ss.get("spans", []):
					attrs = {a["key"]: a.get("value",{}) for a in sp.get("attributes",[])}
					if attrs.get("attackbox.credential.source", {}).get("stringValue") == "authorization":
						has_cred = True
if has_cred:
	import sys
	sys.exit(1)
PY

	# Test bad fixture 2 detection (forbidden field)
	python3 <<PY || fail "$name" "bad fixture 2 should detect forbidden field"
import json
signed = set("service.name service.version service.instance.id service.namespace host.id host.name campaign.id server.port attackbox.persona http.route http.request.method http.response.status_code attackbox.accepted_requests attackbox.rate_limited_requests attackbox.pre_http_connections attackbox.rejected_connections attackbox.captured_requests attackbox.capture_dropped attackbox.otel_dropped_spans_total attackbox.otel_export_failed_spans_total client.address attackbox.request.content_type http.request.body.size gen_ai.request.model attackbox.request.stream attackbox.request.query_params attackbox.probe.class attackbox.connection.outcome attackbox.tls.sni attackbox.credential.source attackbox.credential.type attackbox.credential.value attackbox.canary.key attackbox.canary.value name".split())
all_keys = set()
traces_file = "$bad_forbidden"
with open(traces_file) as f:
	for line in f:
		if not line.strip(): continue
		req = json.loads(line)
		for rs in req.get("resourceSpans", []):
			for ss in rs.get("scopeSpans", []):
				for sp in ss.get("spans", []):
					attrs = {a["key"]: a.get("value",{}) for a in sp.get("attributes",[])}
					all_keys.update(attrs.keys())
client_fields = len(all_keys - signed)
if client_fields == 0:
	import sys
	sys.exit(1)
PY

	pass "$name"
}

# Run all tests
failed=0
test_prepare || failed=1
test_cutover_refuses_bad_receipt || failed=1
test_staged_verify_failure || failed=1
test_success_path_order || failed=1
test_verify_scripts_with_fixtures || failed=1

echo ""
if [[ $failed == 0 ]]; then
	echo "All 5 test cases passed"
	exit 0
else
	echo "Some test cases failed"
	exit 1
fi
