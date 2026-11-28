#!/usr/bin/env bash
set -euo pipefail
umask 077

fail() { printf 'prepare: %s\n' "$*" >&2; exit 1; }
note() { printf 'prepare: %s\n' "$*"; }

[[ $# == 2 ]] || fail 'usage: prepare.sh COMMIT PREVIOUS_RELEASE_DIR'
commit=$1 prev=$2
[[ $commit =~ ^[0-9a-f]{40}$ ]] || fail 'COMMIT must be 40-hex'
[[ -d $prev && -f $prev/bundle.sha256 ]] || fail 'PREVIOUS_RELEASE_DIR must contain bundle.sha256'

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
state=$(git -C "$root" rev-parse --absolute-git-dir)/attackbox-public-ci
receipt=$state/$commit-amd64.verified
[[ -f $receipt ]] || fail "no release-check receipt for $commit (run: COMMIT=$commit PLATFORM=linux/amd64 bash scripts/public-release-check.sh authorize)"

verified=$(<"$receipt")
prefix="$commit linux/amd64 "
[[ $verified == "$prefix"* && ${verified#"$prefix"} =~ ^sha256:[0-9a-f]{64}$ ]] || fail 'invalid release record'

pubname=${ATTACKBOX_PUBLIC_NAME:-}
[[ -n $pubname ]] || fail 'set ATTACKBOX_PUBLIC_NAME (DNS name)'
pubip=$(ssh -G attackbox | awk '/^hostname /{print $2; exit}')
[[ $pubip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "ssh config attackbox has no IP hostname: $pubip"
hostname=$(ssh attackbox 'hostname -s' </dev/null 2>/dev/null) || fail 'cannot get hostname from attackbox'
[[ -n $hostname ]] || fail 'empty hostname from attackbox'

releasesdir=${ATTACKBOX_RELEASES:-$HOME/.local/share/attackbox-public-releases}
reldir=$releasesdir/$commit
[[ ! -e $reldir ]] || fail "$reldir already exists"
mkdir -p -- "$(dirname "$reldir")"
mkdir -m 0700 -- "$reldir"
note "created $reldir"

bundlepath=$state/$commit-amd64.bundle.tar
[[ -f $bundlepath ]] || fail "bundle not found: $bundlepath (run package step)"
sha=$(shasum -a 256 "$bundlepath" | cut -d' ' -f1)
[[ $sha =~ ^[0-9a-f]{64}$ ]] || fail 'bundle sha256 failed'
cp -- "$bundlepath" "$reldir/$commit-amd64.bundle.tar"
printf '%s\n' "$sha" > "$reldir/bundle.sha256"
cp -- "$receipt" "$reldir/$commit-amd64.verified"
note "copied bundle and receipt"

signer=7026F1FDA2A21BC035F17D3B4D9E5BA7BBE1EB29
branch=release/public-$commit
git -C "$root" bundle create "$reldir/public-source.bundle" --quiet "$branch" || fail "branch $branch not found"
mkdir -m 0700 -- "$reldir/source"
git clone --quiet --no-checkout --single-branch --branch "$branch" "$reldir/public-source.bundle" "$reldir/source"
(cd "$reldir/source" && git -c gpg.minTrustLevel=fully verify-commit "$commit") || fail 'signature verification failed'
sig=$(git -C "$reldir/source" log -1 --format='%G? %GF')
[[ $sig == "G $signer" ]] || fail "wrong signature: $sig"
git -C "$reldir/source" checkout -q --detach "$commit"
note "cloned and verified source"

fw_state=$root/.vultr/state.json
[[ -f $fw_state ]] || fail '.vultr/state.json not found'
instance_id=$(jq -er .instance_id "$fw_state")
firewall_id=$(jq -er .firewall_id "$fw_state")
ssh_rule_id=$(jq -er .ssh_rule_id "$fw_state")
admin_cidr=$(jq -er .admin_cidr "$fw_state")
[[ $instance_id =~ ^[0-9a-f-]+$ && $firewall_id =~ ^[0-9a-f-]+$ && $ssh_rule_id =~ ^[0-9]+$ && $admin_cidr =~ ^[0-9.]+/32$ ]] || fail 'invalid state.json'

ports=443,80,1234,3000,4000,8000,8080,8188,8888,11434
mkdir -m 0700 -- "$reldir/firewall"
cp -- "$root/scripts/public-firewall-ledger.sh" "$reldir/public-firewall-ledger.sh"

kit_root=$(dirname "$(dirname "${BASH_SOURCE[0]}")")/public-release
for script in cutover.sh stage.sh firewall.sh verify-staged.py verify-public.py host-proof.py; do
	sed -e "s|@COMMIT@|$commit|g" \
		-e "s|@BUNDLE_SHA@|$sha|g" \
		-e "s|@PREV_RELEASE@|${prev##*/}|g" \
		-e "s|@PUBLIC_IP@|$pubip|g" \
		-e "s|@PUBLIC_NAME@|$pubname|g" \
		-e "s|@HOSTNAME@|$hostname|g" \
		-e "s|@INSTANCE_ID@|$instance_id|g" \
		-e "s|@FIREWALL_ID@|$firewall_id|g" \
		-e "s|@SSH_RULE_ID@|$ssh_rule_id|g" \
		-e "s|@ADMIN_CIDR@|$admin_cidr|g" \
		-e "s|@PORTS@|$ports|g" \
		-e "s|@REPO_ROOT@|$root|g" \
		-e "s|@RELEASES_DIR@|$releasesdir|g" \
		"$kit_root/$script.in" > "$reldir/$script"
	chmod 0700 "$reldir/$script"
done
note "generated cutover scripts"

printf 'Release kit ready at %s\n' "$reldir"
printf 'Next: cd %s && ./cutover.sh\n' "$reldir"
