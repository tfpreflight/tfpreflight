#!/usr/bin/env bash
# Tests for scripts/release.sh. They use a fake "gh" and a local folder as
# the remote, so nothing here touches GitHub. Run: bash scripts/release_test.sh
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPT="$HERE/release.sh"
ROOT="$(mktemp -d)"
trap 'rm -rf "$ROOT"' EXIT

pass=0
failed=0

# A fake gh. It prints what the real gh would print after --jq, taken from
# the files in $FAKE (one file per answer).
mkdir -p "$ROOT/bin"
cat > "$ROOT/bin/gh" <<'SHIM'
#!/usr/bin/env bash
args="$*"
f() { [ -f "$FAKE/$1" ] && cat "$FAKE/$1"; }
case "$1 $2" in
  "auth status") exit 0 ;;
  "pr list") f open_prs ;;
  "api repos/"*) f merged_pr ;;
  "run list")
    case "$args" in
      *ci.yml*) f ci_runs ;;
      *release.yml*) f release_run ;;
    esac ;;
  "run view")
    case "$args" in
      *status,conclusion*) f run_state ;;
      *) echo "https://example.invalid/run/1" ;;
    esac ;;
  "release view") [ -f "$FAKE/release" ] && cat "$FAKE/release" || exit 1 ;;
  *) echo "fake gh: unexpected: $args" >&2; exit 2 ;;
esac
SHIM
chmod +x "$ROOT/bin/gh"

cat > "$ROOT/gitconfig" <<CFG
[user]
	name = Test
	email = test@example.invalid
[init]
	defaultBranch = main
[url "$ROOT/remote.git"]
	insteadOf = https://github.com/tfpreflight/tfpreflight.git
CFG

# setup builds a fresh remote, a clone on main, and a passing fake gh.
setup() {
  rm -rf "$ROOT/remote.git" "$ROOT/work" "$ROOT/fake"
  mkdir -p "$ROOT/fake"
  export FAKE="$ROOT/fake"
  export GIT_CONFIG_GLOBAL="$ROOT/gitconfig"
  export PATH="$ROOT/bin:$PATH"
  export TFP_RELEASE_POLL_SECONDS=0 TFP_RELEASE_WAIT_MINUTES=0
  git init -q --bare "$ROOT/remote.git"
  git init -q "$ROOT/work"
  cd "$ROOT/work" || exit 1
  git remote add origin https://github.com/tfpreflight/tfpreflight.git
  printf '# Changelog\n\n## 0.1.0-beta.7 (2026-11-09)\n\n- Something.\n' > CHANGELOG.md
  git add . && git commit -q -m "Release 0.1.0-beta.7" && git push -q origin main
  echo 0 > "$FAKE/open_prs"
  echo 42 > "$FAKE/merged_pr"
  echo "completed success" > "$FAKE/ci_runs"
  echo 9001 > "$FAKE/release_run"
  echo "completed success" > "$FAKE/run_state"
  echo "false https://example.invalid/rel tfpreflight_0.1.0-beta.7_checksums.txt,a.tar.gz" > "$FAKE/release"
}

# check NAME WANT_EXIT WANT_TEXT -- ARGS...   (runs release.sh in $ROOT/work)
check() {
  local name="$1" want_exit="$2" want_text="$3"
  shift 4
  local out code
  out="$(cd "$ROOT/work" && "$SCRIPT" "$@" 2>&1)"
  code=$?
  if [ "$code" = "$want_exit" ] && grep -qF -- "$want_text" <<< "$out"; then
    pass=$((pass + 1))
    echo "PASS $name"
  else
    failed=$((failed + 1))
    echo "FAIL $name (exit $code, wanted $want_exit and \"$want_text\")"
    echo "$out" | sed 's/^/     /'
  fi
}

remote_has_tag() { git -C "$ROOT/remote.git" rev-parse -q --verify "refs/tags/$1" > /dev/null; }
assert() {
  if eval "$2"; then pass=$((pass + 1)); echo "PASS $1"; else failed=$((failed + 1)); echo "FAIL $1"; fi
}

setup; check "no version" 1 "usage:" -- 
setup; check "version with v" 1 "no leading v" -- v0.1.0-beta.7
setup; check "two versions" 1 "one version only" -- 0.1.0 0.2.0
setup; check "unknown option" 1 "unknown option" -- 0.1.0-beta.7 --force

setup
check "dry run passes" 0 "All checks passed" -- 0.1.0-beta.7
assert "dry run makes no local tag" '! git -C "$ROOT/work" rev-parse -q --verify refs/tags/v0.1.0-beta.7 >/dev/null'
assert "dry run pushes no tag" '! remote_has_tag v0.1.0-beta.7'

setup; git checkout -q -b other; check "not on main" 1 "switch to main" -- 0.1.0-beta.7
setup; echo x > dirty.txt; check "dirty tree" 1 "uncommitted changes" -- 0.1.0-beta.7
setup; git commit -q --allow-empty -m local; check "unpushed commit" 1 "not on origin/main" -- 0.1.0-beta.7
setup; git remote set-url origin https://github.com/someone/else.git; check "wrong origin" 1 "origin is not" -- 0.1.0-beta.7

setup; git tag -a v0.1.0-beta.7 -m x; check "local tag exists" 1 "already exists here" -- 0.1.0-beta.7
setup; git tag -a v0.1.0-beta.7 -m x; git push -q origin v0.1.0-beta.7; git tag -d v0.1.0-beta.7 > /dev/null
check "remote tag exists" 1 "already exists" -- 0.1.0-beta.7

setup; check "version not in CHANGELOG" 1 "no \"## 0.1.0-beta.8" -- 0.1.0-beta.8
setup; printf '# Changelog\n\n## 0.1.0-beta.7\n' > CHANGELOG.md; git commit -q -am undated; git push -q origin main
check "CHANGELOG not dated" 1 "no date" -- 0.1.0-beta.7
setup; echo 1 > "$FAKE/open_prs"; check "open PR for version" 1 "open PR mentions" -- 0.1.0-beta.7
setup; : > "$FAKE/merged_pr"; check "release PR not merged" 1 "not from a merged PR" -- 0.1.0-beta.7
setup; : > "$FAKE/ci_runs"; check "no CI run" 1 "no CI run found" -- 0.1.0-beta.7
setup; echo "completed failure" > "$FAKE/ci_runs"; check "CI red" 1 "not green" -- 0.1.0-beta.7
setup; printf 'completed success\nin_progress \n' > "$FAKE/ci_runs"; check "CI still running" 1 "not green" -- 0.1.0-beta.7

setup
check "go releases" 0 "release v0.1.0-beta.7 is published" -- 0.1.0-beta.7 --go
assert "go pushes the tag" 'remote_has_tag v0.1.0-beta.7'
assert "tag is annotated" '[ "$(git -C "$ROOT/remote.git" cat-file -t refs/tags/v0.1.0-beta.7)" = tag ]'
setup
check "go prints the approval link" 0 "https://example.invalid/run/1" -- 0.1.0-beta.7 --go

setup; echo "completed failure" > "$FAKE/run_state"; check "go: run fails" 1 "ended with: failure" -- 0.1.0-beta.7 --go
setup; rm "$FAKE/release"; check "go: release missing" 1 "does not exist" -- 0.1.0-beta.7 --go
setup; echo "true https://example.invalid/rel tfpreflight_0.1.0-beta.7_checksums.txt" > "$FAKE/release"
check "go: release is a draft" 1 "still a draft" -- 0.1.0-beta.7 --go
setup; echo "false https://example.invalid/rel a.tar.gz" > "$FAKE/release"; check "go: no checksum file" 1 "no tfpreflight_0.1.0-beta.7_checksums.txt" -- 0.1.0-beta.7 --go
setup; rm "$FAKE/release_run"; check "go: run never starts" 1 "did not start" -- 0.1.0-beta.7 --go
setup; echo "completed failure" > "$FAKE/ci_runs"; check "go refused on red CI" 1 "not green" -- 0.1.0-beta.7 --go
assert "refused go pushes no tag" '! remote_has_tag v0.1.0-beta.7'
assert "refused go makes no local tag" '! git -C "$ROOT/work" rev-parse -q --verify refs/tags/v0.1.0-beta.7 >/dev/null'

echo
echo "$pass passed, $failed failed"
[ "$failed" = 0 ]
