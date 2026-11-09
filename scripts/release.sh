#!/usr/bin/env bash
# release.sh VERSION [--go]
#
# Releases tfpreflight. VERSION has no leading "v", e.g. 0.1.0-beta.7.
#
# Without --go it is a dry run: it makes every check and prints what it would
# do. Nothing is created, changed or pushed.
#
# With --go it also pulls main, creates the annotated tag, pushes it, prints
# the link to the release run for you to approve, and then waits until the
# release is published and checks that it exists.
#
# Settings for tests only:
#   TFP_RELEASE_POLL_SECONDS  seconds between checks while waiting (default 10)
#   TFP_RELEASE_WAIT_MINUTES  how long to wait for each stage (default 60)
set -euo pipefail

REPO="tfpreflight/tfpreflight"
POLL="${TFP_RELEASE_POLL_SECONDS:-10}"
WAIT_MIN="${TFP_RELEASE_WAIT_MINUTES:-60}"

fail() {
  echo "REFUSED: $*" >&2
  exit 1
}

ok() {
  echo "ok   $*"
}

version=""
go=0
for arg in "$@"; do
  case "$arg" in
    --go) go=1 ;;
    -h | --help)
      sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    -*) fail "unknown option $arg" ;;
    *)
      [ -z "$version" ] || fail "give one version only"
      version="$arg"
      ;;
  esac
done

[ -n "$version" ] || fail "usage: scripts/release.sh VERSION [--go]"
if ! [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
  fail "\"$version\" is not a version like 0.1.0-beta.7 (no leading v)"
fi
tag="v$version"

command -v git > /dev/null || fail "git is not installed"
command -v gh > /dev/null || fail "gh (GitHub CLI) is not installed"
gh auth status > /dev/null 2>&1 || fail "gh is not logged in; run: gh auth login"

if [ "$go" = 1 ]; then
  echo "Releasing $tag (--go: this will create and push the tag)"
else
  echo "Dry run for $tag (nothing will be created or pushed; add --go to release)"
fi

# --- Where we are -----------------------------------------------------------

cd "$(git rev-parse --show-toplevel)"
origin_url="$(git config --get remote.origin.url || true)"
case "$origin_url" in
  *"github.com/$REPO"* | *"github.com:$REPO"*) ok "origin is $REPO" ;;
  *) fail "origin is not $REPO; run this in the tfpreflight repo" ;;
esac

branch="$(git rev-parse --abbrev-ref HEAD)"
[ "$branch" = main ] || fail "you are on \"$branch\"; switch to main first"
ok "on main"

[ -z "$(git status --porcelain)" ] || fail "the working tree has uncommitted changes"
ok "working tree is clean"

git fetch --quiet origin main
git fetch --quiet --tags origin
head_sha="$(git rev-parse origin/main)"
ok "origin/main is ${head_sha:0:7}"

if [ -n "$(git rev-list origin/main..HEAD)" ]; then
  fail "local main has commits that are not on origin/main"
fi

# --- The tag must be new ----------------------------------------------------

if git rev-parse -q --verify "refs/tags/$tag" > /dev/null; then
  fail "tag $tag already exists here"
fi
if [ -n "$(git ls-remote --tags origin "refs/tags/$tag")" ]; then
  fail "tag $tag already exists on origin"
fi
ok "tag $tag does not exist yet"

# --- CHANGELOG (read from origin/main, the commit that will be tagged) ------

heading_re="^## ${version//./\\.} \\([0-9]{4}-[0-9]{2}-[0-9]{2}\\)\$"
heading="$(git show "origin/main:CHANGELOG.md" | grep -E "$heading_re" || true)"
if [ -z "$heading" ]; then
  if git show "origin/main:CHANGELOG.md" | grep -q "^## ${version//./\\.}"; then
    fail "CHANGELOG.md has $version but with no date like (2026-11-06)"
  fi
  fail "CHANGELOG.md on main has no \"## $version (YYYY-MM-DD)\" section"
fi
ok "CHANGELOG has: $heading"

# --- The release PR must be merged ------------------------------------------

open_prs="$(gh pr list --repo "$REPO" --state open --search "$version in:title" \
  --json number --jq 'length')"
[ "$open_prs" = 0 ] || fail "an open PR mentions $version in its title; merge or close it"

change_sha="$(git log origin/main -S"## $version (" --format=%H -- CHANGELOG.md | tail -n 1)"
[ -n "$change_sha" ] || fail "cannot find the commit that added $version to CHANGELOG.md"
merged_pr="$(gh api "repos/$REPO/commits/$change_sha/pulls" \
  --jq '[.[] | select(.merged_at != null)] | .[0].number // empty')"
[ -n "$merged_pr" ] || fail "commit ${change_sha:0:7} (which added $version to CHANGELOG.md) is not from a merged PR"
ok "release PR #$merged_pr is merged"

# --- CI on main must be green -----------------------------------------------

runs="$(gh run list --repo "$REPO" --workflow ci.yml --commit "$head_sha" \
  --json status,conclusion --jq '.[] | "\(.status) \(.conclusion)"')"
[ -n "$runs" ] || fail "no CI run found for main (${head_sha:0:7}); wait for it to start"
if [ -n "$(echo "$runs" | grep -v '^completed success$' || true)" ]; then
  fail "CI on main (${head_sha:0:7}) is not green: $(echo "$runs" | sort -u | tr '\n' ',' | sed 's/,$//')"
fi
ok "CI on main (${head_sha:0:7}) is green"

# --- Stop here on a dry run -------------------------------------------------

if [ "$go" = 0 ]; then
  echo
  echo "All checks passed. With --go I would:"
  echo "  1. pull main (fast-forward only)"
  echo "  2. create the annotated tag $tag on ${head_sha:0:7} and push it"
  echo "  3. print the link to the release run for you to approve"
  echo "  4. wait for the publish and check that the release exists"
  exit 0
fi

# --- Tag and push -----------------------------------------------------------

git merge --quiet --ff-only origin/main
[ "$(git rev-parse HEAD)" = "$head_sha" ] || fail "main did not move to ${head_sha:0:7}"
git tag -a "$tag" -m "tfpreflight $version" "$head_sha"
git push --quiet origin "refs/tags/$tag"
ok "pushed tag $tag"

# --- Find the release run and wait ------------------------------------------

deadline=$((SECONDS + WAIT_MIN * 60))
run_id=""
while [ -z "$run_id" ]; do
  run_id="$(gh run list --repo "$REPO" --workflow release.yml --branch "$tag" \
    --json databaseId --jq '.[0].databaseId // empty' || true)"
  [ -z "$run_id" ] || break
  [ "$SECONDS" -lt "$deadline" ] || fail "the release run did not start for $tag"
  sleep "$POLL"
done
run_url="$(gh run view "$run_id" --repo "$REPO" --json url --jq .url)"
echo
echo "Approve the release here (environment: release):"
echo "  $run_url"
echo
echo "Waiting for the run to finish (up to $WAIT_MIN minutes)..."

last=""
while :; do
  state="$(gh run view "$run_id" --repo "$REPO" --json status,conclusion \
    --jq '"\(.status) \(.conclusion)"' || true)"
  if [ -n "$state" ] && [ "$state" != "$last" ]; then
    echo "  run: $state"
    last="$state"
  fi
  case "$state" in
    "completed success") break ;;
    completed*) fail "the release run ended with: ${state#completed }. See $run_url" ;;
  esac
  [ "$SECONDS" -lt "$deadline" ] || fail "timed out waiting for the release run. See $run_url"
  sleep "$POLL"
done

# --- Check the release ------------------------------------------------------

release="$(gh release view "$tag" --repo "$REPO" --json isDraft,url,assets \
  --jq '"\(.isDraft) \(.url) \([.assets[].name] | join(","))"' || true)"
[ -n "$release" ] || fail "the run passed but release $tag does not exist"
is_draft="${release%% *}"
rest="${release#* }"
release_url="${rest%% *}"
assets="${rest#* }"
[ "$is_draft" = false ] || fail "release $tag exists but is still a draft: $release_url"
case ",$assets," in
  *",tfpreflight_${version}_checksums.txt,"*) ;;
  *) fail "release $tag has no tfpreflight_${version}_checksums.txt: $release_url" ;;
esac
ok "release $tag is published with $(echo "$assets" | tr ',' '\n' | wc -l | tr -d ' ') files"
echo "  $release_url"
