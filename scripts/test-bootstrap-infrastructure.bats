#!/usr/bin/env bats
# Hermetic native-bootstrap lifecycle checks. No host/account/network mutations.
setup() {
  export FIXTURE="$BATS_TEST_TMPDIR/project"
  mkdir -p "$FIXTURE/scripts" "$FIXTURE/deploy/newrelic" "$FIXTURE/bootstrap" "$FIXTURE/bin" "$FIXTURE/etc/newrelic-infra/logging.d" "$FIXTURE/usr/local/sbin" "$FIXTURE/usr/bin"
  cp "$BATS_TEST_DIRNAME/bootstrap-infrastructure.sh" "$FIXTURE/scripts/"
  cp "$BATS_TEST_DIRNAME/../deploy/newrelic/host-logging.yml" "$FIXTURE/deploy/newrelic/"
  cp "$BATS_TEST_DIRNAME/../deploy/newrelic/edge-logging.yml" "$FIXTURE/deploy/newrelic/"
  printf '#!/bin/sh\nexit 0\n' >"$FIXTURE/newrelic"
  chmod +x "$FIXTURE/newrelic"
  tar -czf "$FIXTURE/fixture.tar.gz" -C "$FIXTURE" newrelic
  checksum=$(shasum -a 256 "$FIXTURE/fixture.tar.gz" | cut -d' ' -f1)
  printf 'NRCLI_VERSION=0.117.0\nNRCLI_LINUX_AMD64_SHA256=%s\n' "$checksum" >"$FIXTURE/deploy/newrelic/version.env"
  # Redirect fixed system paths and the Linux/root gate in this disposable test copy only.
  python3 - "$FIXTURE" <<'PY'
import pathlib,sys
r=pathlib.Path(sys.argv[1]); p=r/'scripts/bootstrap-infrastructure.sh'; s=p.read_text()
s=s.replace('[[ $(uname -s)/$(uname -m) == Linux/x86_64 && $EUID == 0 ]]', '[[ ${TEST_LINUX_ROOT:-yes} == yes ]]')
for path in ['/usr/local/sbin/attackbox-deploy','/usr/bin/newrelic-infra','/etc/newrelic-infra']:
    s=s.replace(path,str(r)+path)
p.write_text(s)
PY
  printf '#!/bin/sh\nprintf "refresh %%s\\n" "$*" >>"$FIXTURE/calls"\n' >"$FIXTURE/usr/local/sbin/attackbox-deploy"
  printf '#!/bin/sh\nexit 0\n' >"$FIXTURE/usr/bin/newrelic-infra"
  printf 'import os\np=os.environ["FIXTURE"]+"/etc/newrelic-infra.yml"\nif os.path.isfile(p): os.chmod(p, 0o600)\n' >"$FIXTURE/deploy/newrelic/configure-agent.py"
  printf 'import os\nassert os.path.exists(os.environ["FIXTURE"] + "/etc/newrelic-infra.yml")\n' >"$FIXTURE/deploy/newrelic/verify-config.py"
  cat >"$FIXTURE/bin/curl" <<'SH'
#!/bin/bash
printf 'curl %s\n' "$*" >>"$FIXTURE/calls"
if [[ "$*" == *18003* ]]; then printf '{"checks":{"health":{"healthy":true}}}'; exit 0; fi
while [[ $# -gt 0 ]]; do
  if [[ $1 == -o ]]; then cp "$FIXTURE/fixture.tar.gz" "$2"; exit; fi
  shift
done
exit 1
SH
  cat >"$FIXTURE/bin/systemctl" <<'SH'
#!/bin/bash
printf 'systemctl %s\n' "$*" >>"$FIXTURE/calls"
case "$*" in
  *newrelic-infra*) [[ -e "$FIXTURE/installed" ]] ;;
  *) exit 0 ;;
esac
SH
  cat >"$FIXTURE/bin/dpkg-query" <<'SH'
#!/bin/bash
[[ -e "$FIXTURE/installed" ]] || exit 1
printf 'install ok installed\n'
SH
  cat >"$FIXTURE/bin/nft" <<'SH'
#!/bin/bash
printf 'nft %s\n' "$*" >>"$FIXTURE/calls"
[[ ${FAIL_NFT:-} != 1 ]]
SH
  cat >"$FIXTURE/bin/env" <<'SH'
#!/bin/bash
printf 'env %s\n' "$*" >>"$FIXTURE/calls"
IFS= read -r key
[[ $key == NRAK-$(printf '%024d' 0) ]] || exit 2
printf 'license_key: test\n' >"$FIXTURE/etc/newrelic-infra.yml"
chmod 0644 "$FIXTURE/etc/newrelic-infra.yml"
[[ ${FAIL_INSTALL:-} != 1 ]] || { printf 'secret %s\n' "$key"; exit 3; }
touch "$FIXTURE/installed"
printf 'Docker logs\n' >"$FIXTURE/etc/newrelic-infra/logging.d/discovered.yml"
printf 'CLI logs\n' >"$FIXTURE/etc/newrelic-infra/logging.d/logging.yml"
SH
  printf '#!/bin/sh\nexit 0\n' >"$FIXTURE/bin/chown"
  chmod +x "$FIXTURE/bin/"* "$FIXTURE/usr/local/sbin/attackbox-deploy" "$FIXTURE/usr/bin/newrelic-infra"
  export PATH="$FIXTURE/bin:$PATH"
  export SUBJECT="$FIXTURE/scripts/bootstrap-infrastructure.sh"
}

@test "dry-run makes no download or service calls" {
  run bash "$SUBJECT" --dry-run
  [ "$status" -eq 0 ]
  [ ! -e "$FIXTURE/calls" ]
}

@test "stage verifies checksum and rerun avoids download" {
  run bash "$SUBJECT" --stage "$FIXTURE/bootstrap"
  [ "$status" -eq 0 ]
  [ -f "$FIXTURE/bootstrap/newrelic-cli-linux-amd64.tar.gz" ]
  run bash "$SUBJECT" --stage "$FIXTURE/bootstrap"
  [ "$status" -eq 0 ]
  [ "$(grep -c '^curl ' "$FIXTURE/calls")" -eq 1 ]
}

@test "wrong checksum fails and no final archive remains" {
  printf corrupt >>"$FIXTURE/fixture.tar.gz"
  run bash "$SUBJECT" --stage "$FIXTURE/bootstrap"
  [ "$status" -ne 0 ]
  [[ "$output" == *SHA256*mismatch* ]]
  [ ! -e "$FIXTURE/bootstrap/newrelic-cli-linux-amd64.tar.gz" ]
}

@test "missing archive and missing API key fail before installer" {
  run bash "$SUBJECT" --apply </dev/null
  [ "$status" -ne 0 ]
  [[ "$output" == *archive* ]]
  cp "$FIXTURE/fixture.tar.gz" "$FIXTURE/bootstrap/newrelic-cli-linux-amd64.tar.gz"
  run bash "$SUBJECT" --apply </dev/null
  [ "$status" -ne 0 ]
  [[ "$output" == *key*required* ]]
  ! grep -q '^env ' "$FIXTURE/calls"
}

@test "apply confines key to stdin and closes install-only egress" {
  cp "$FIXTURE/fixture.tar.gz" "$FIXTURE/bootstrap/newrelic-cli-linux-amd64.tar.gz"
  run bash "$SUBJECT" --apply <<<NRAK-$(printf '%024d' 0)
  [ "$status" -eq 0 ]
  ! grep -q 'NRAK-' "$FIXTURE/calls"
  [[ "$output" != *NRAK-* ]]
  grep -q 'refresh --refresh-install-sets' "$FIXTURE/calls"
  grep -q 'nft flush set inet attackbox nr_install_ipv4' "$FIXTURE/calls"
  grep -q 'nft flush set inet attackbox nr_install_ipv6' "$FIXTURE/calls"
  [ -f "$FIXTURE/etc/newrelic-infra/logging.d/attackbox-host.yml" ]
  [ ! -e "$FIXTURE/etc/newrelic-infra/logging.d/discovered.yml" ]
  [ -f "$FIXTURE/etc/newrelic-infra/bootstrap-backup/discovered.yml" ]
}

@test "failed installer never leaks API key and cleans egress" {
  cp "$FIXTURE/fixture.tar.gz" "$FIXTURE/bootstrap/newrelic-cli-linux-amd64.tar.gz"
  export FAIL_INSTALL=1
  run bash "$SUBJECT" --apply <<<NRAK-$(printf '%024d' 0)
  [ "$status" -ne 0 ]
  [[ "$output" != *NRAK-* ]]
  grep -q 'nft flush set inet attackbox nr_install_ipv4' "$FIXTURE/calls"
  [ ! -e "$FIXTURE/installed" ]
  [ "$(python3 -c 'import os,stat; print(oct(stat.S_IMODE(os.stat(os.environ["FIXTURE"]+"/etc/newrelic-infra.yml").st_mode)))')" = 0o600 ]
}

@test "healthy rerun preserves config and does not consume API key" {
  touch "$FIXTURE/installed"
  printf operator >"$FIXTURE/etc/newrelic-infra.yml"
  run bash "$SUBJECT" --apply </dev/null
  [ "$status" -eq 0 ]
  [ "$(cat "$FIXTURE/etc/newrelic-infra.yml")" = operator ]
  ! grep -q '^env ' "$FIXTURE/calls"
  ! grep -q 'refresh-install' "$FIXTURE/calls"
  cmp "$FIXTURE/deploy/newrelic/edge-logging.yml" "$FIXTURE/etc/newrelic-infra/logging.d/attackbox-edge.yml"
}

@test "verify refuses missing agent" {
  run bash "$SUBJECT" --verify
  [ "$status" -ne 0 ]
}
