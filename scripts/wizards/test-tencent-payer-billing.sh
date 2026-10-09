#!/usr/bin/env bash
#
# Dry run of tencent-payer-billing.sh: drives it end to end with scripted
# answers against stubbed tccli, kubectl, curl and gh in a temp HOME and git
# repo, then checks the config stage 8 prints. Nothing reaches Tencent or a
# cluster: PATH holds only the stubs and /usr/bin:/bin.
#
#   bash scripts/wizards/test-tencent-payer-billing.sh
#
# It runs the wizard with the bash that runs it, so run it once with
# /bin/bash (3.2 on macOS) and once with a current bash.

set -euo pipefail

wizard="$(cd "$(dirname "$0")" && pwd)/tencent-payer-billing.sh"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
BASE_ARN="qcs::cam::uin/100099:roleName/keel-api"
failures=0

# check LABEL CMD...: runs CMD and records the result under LABEL.
check() {
  local label=$1
  shift
  if "$@"; then printf 'ok   %s\n' "$label"; else printf 'FAIL %s\n' "$label"; failures=$((failures + 1)); fi
}
has() { grep -qF -- "$2" "$1"; }
lacks() { [[ -f "$1" ]] && ! grep -qiF -- "$2" "$1"; }
eq() { [[ "$1" == "$2" ]]; }

mkdir -p "$work/bin"
cat > "$work/bin/tccli" <<'STUB'
#!/bin/bash
set -u
echo "$*" >> "$STUB_STATE/calls"
svc=$1 act=$2
shift 2
filter="" role="" doc="" pname="" pid=""
while (($#)); do
  case $1 in
    --filter) filter=$2; shift ;;
    --RoleName|--AttachRoleName) role=$2; shift ;;
    --PolicyDocument) doc=$2; shift ;;
    --PolicyName) pname=$2; shift ;;
    --PolicyId) pid=$2; shift ;;
  esac
  shift
done
[[ "${STUB_FAIL:-}" == "$act" ]] && { echo "[TencentCloudSDKException] code:InvalidParameter.PolicyDocumentError message:stub refused $act" >&2; exit 1; }
case "$svc $act" in
  "sts GetCallerIdentity") echo '"200045645249"' ;;
  "cam GetUserAppId") echo '1250000000' ;;
  "cam GetRole")
    [[ -f "$STUB_STATE/role-$role" ]] || { echo "[TencentCloudSDKException] code:ResourceNotFound.RoleNotExist message:role not exist" >&2; exit 1; }
    case $filter in
      RoleInfo.RoleId) echo '"4611686018427387904"' ;;
      RoleInfo.PolicyDocument) python3 -c 'import json,sys; print(json.dumps(open(sys.argv[1]).read()))' "$STUB_STATE/role-$role" ;;
    esac ;;
  "cam CreateRole"|"cam UpdateAssumeRolePolicy") printf '%s' "$doc" > "$STUB_STATE/role-$role"; echo '{}' ;;
  "cam ListPolicies") if [[ -f "$STUB_STATE/policy" ]]; then echo '"9001"'; else echo 'null'; fi ;;
  "cam CreatePolicy") printf '%s' "$doc" > "$STUB_STATE/policy"; echo '9001' ;;
  "cam UpdatePolicy") printf '%s' "$doc" > "$STUB_STATE/policy"; echo '{}' ;;
  "cam AttachRolePolicy")
    [[ "$pid" == 9001 ]] && pname=KeelBillBucketRead
    echo "$pname" >> "$STUB_STATE/attached-$role"; echo '{}' ;;
  "cam ListAttachedRolePolicies")
    sed 's/.*/"&"/' "$STUB_STATE/attached-$role" 2>/dev/null | paste -sd, - | sed 's/^/[/;s/$/]/' ;;
  "billing "*) echo '{"DetailSet":[],"Total":0}' ;;
  *) echo "stub tccli: unexpected $svc $act" >&2; exit 2 ;;
esac
STUB
cat > "$work/bin/kubectl" <<STUB
#!/bin/bash
echo "\$*" >> "\$STUB_STATE/kubectl-calls"
case "\$*" in
  *" get sa "*) printf '%s' '$BASE_ARN' ;;
  *" logs "*) echo 'tencent bill sync new_files=2' ;;
  *) exit 1 ;;
esac
STUB
printf '#!/bin/bash\nprintf 403\n' > "$work/bin/curl"
cat > "$work/bin/gh" <<'STUB'
#!/bin/bash
echo "$*" >> "$STUB_STATE/gh-calls"
exit 1
STUB
printf '#!/bin/bash\nexit 0\n' > "$work/bin/open"
cp "$work/bin/open" "$work/bin/xdg-open"
chmod +x "$work/bin/"*

# new_repo DIR: a git repo holding the wizard, with an empty HOME and stub state.
new_repo() {
  mkdir -p "$1/repo/scripts/wizards" "$1/home" "$1/state"
  cp "$wizard" "$1/repo/scripts/wizards/"
  git -C "$1/repo" init -q
}

# run DIR ANSWERS [VAR=VALUE...]: runs the wizard with one answer per line.
run() {
  local dir=$1 answers=$2
  shift 2
  (cd "$dir/repo" && printf '%s\n' "$answers" | env -i HOME="$dir/home" PATH="$work/bin:/usr/bin:/bin" TERM=dumb \
    STUB_STATE="$dir/state" "$@" "$BASH" scripts/wizards/tencent-payer-billing.sh) > "$dir/out" 2>&1
}

fresh_answers=$(printf '%s\n' \
  "" "" "" "" \
  "" "" "" y "" "" "" \
  "" "" \
  y "" \
  y "" y "" "" \
  100001 "" "" "" "" n "" \
  y bills/focus/ n n "" \
  "" n y "")
resume_answers=$(printf '%s\n' "" n n n n n n n "" n y "")


expect_config() {
  local dir=$1 label=$2 kv
  sed -n '/Stage 8\/8/,$p' "$dir/out" > "$dir/stage8"
  check "$label: reaches stage 8" test -s "$dir/stage8"
  for kv in KEEL_TENCENT_BILL_BUCKET=keel-bills-1250000000 KEEL_TENCENT_BILL_PREFIX=bills/focus/ \
    KEEL_TENCENT_PAYER_UIN=200045645249 KEEL_TENCENT_REGION=ap-bangkok KEEL_TENCENT_BILL_MODE=cumulative \
    KEEL_TENCENT_BILL_ROLE=KeelBillReader KEEL_TENCENT_BUDGETS=1; do
    check "$label: prints $kv" grep -qxF "    $kv" "$dir/stage8"
  done
  check "$label: no empty value" eq "$(grep -E '^    KEEL_[A-Z_]+=$' "$dir/stage8" || true)" ""
  check "$label: no ServiceAccount annotate step" lacks "$dir/out" annotate
  check "$label: says keel-api keeps its base role" has "$dir/stage8" "keeps its base role ($BASE_ARN)"
  check "$label: no unbound variable" lacks "$dir/out" "unbound variable"
  check "$label: finishes" has "$dir/out" "Setup complete"
}

one="$work/one"
new_repo "$one"
status=0; run "$one" "$fresh_answers" || status=$?
check "fresh: exit 0" eq "$status" 0
expect_config "$one" fresh
check "fresh: stage 7 knows the delivery date" lacks "$one/out" "an unknown date"
trusted=$(python3 -c 'import json,sys; print(",".join(json.load(open(sys.argv[1]))["statement"][0]["principal"]["qcs"]))' "$one/repo/.keel/trust.json" || true)
check "fresh: trust names exactly the base role" eq "$trusted" "$BASE_ARN"
check "fresh: created role trusts the base role" has "$one/state/role-KeelBillReader" "\"qcs\":[\"$BASE_ARN\"]"
check "fresh: created role allows sts:AssumeRole" has "$one/state/role-KeelBillReader" '"name/sts:AssumeRole"'
check "fresh: verified the trust read-only" has "$one/out" "trust allows sts:AssumeRole from $BASE_ARN only"
check "fresh: no OIDC provider call" lacks "$one/state/calls" OIDC
for f in calls policy role-KeelBillReader; do
  check "fresh: no budget action in tccli $f" lacks "$one/state/$f" budget
done
check "fresh: budget policy written for the base role" has "$one/repo/.keel/base-budgets.json" '"name/billing:CreateBudget"'
check "fresh: budget policy pointed at the base role" has "$one/out" "Attach .keel/base-budgets.json to Keel's base role"
check "fresh: base role grant names the bill role" has "$one/repo/.keel/base-assume.json" '"resource":["qcs::cam::uin/200045645249:roleName/KeelBillReader"]'
check "fresh: kubectl only reads" eq "$(grep -v -e '^-n keel get sa keel-api ' -e '^-n keel logs ' "$one/state/kubectl-calls" || true)" ""

mv "$one/out" "$one/out.fresh"
calls_before=$(wc -l < "$one/state/calls")
status=0; run "$one" "$resume_answers" || status=$?
check "resume: exit 0" eq "$status" 0
expect_config "$one" resume
check "resume: no tccli call" eq "$(wc -l < "$one/state/calls")" "$calls_before"

two="$work/two"
new_repo "$two"
status=0; run "$two" "$fresh_answers" STUB_FAIL=CreatePolicy || status=$?
check "failing tccli: wizard stops" test "$status" != 0
check "failing tccli: names the call" has "$two/out" "tccli cam CreatePolicy failed"
check "failing tccli: shows its error" has "$two/out" "stub refused CreatePolicy"

if (( failures )); then
  printf '\n%s check(s) failed. Wizard output:\n' "$failures"
  for f in "$one/out.fresh" "$one/out" "$two/out"; do printf '\n--- %s\n' "$f"; cat "$f"; done
  exit 1
fi
printf '\nall checks passed with %s\n' "$BASH_VERSION"
