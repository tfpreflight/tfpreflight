#!/bin/sh
set -eu

repository="tfpreflight/tfpreflight"
# The release workflow signs the checksum file keylessly; these are the
# identity and issuer its certificate must carry.
certificate_identity_regexp='^https://github.com/tfpreflight/tfpreflight/.github/workflows/release.yml@refs/tags/v'
certificate_oidc_issuer='https://token.actions.githubusercontent.com'

fail() {
  printf 'tfpreflight installer: %s\n' "$*" >&2
  exit 1
}

warn() {
  printf 'tfpreflight installer: warning: %s\n' "$*" >&2
}

usage() {
  cat <<'USAGE'
Usage: install.sh [--require-signature]

  --require-signature  fail unless cosign is installed and verifies the
                       release's signed checksum file

Environment:
  TFPREFLIGHT_VERSION           release tag to install, such as v0.1.0
                                (default: the newest v* release, betas included)
  TFPREFLIGHT_INSTALL_DIR       where to install (default: /usr/local/bin if
                                writable, else ~/.local/bin)
  TFPREFLIGHT_RELEASES_URL      release list to choose from (default: GitHub's)
  TFPREFLIGHT_RELEASE_BASE_URL  where to download the release files from
USAGE
}

require_signature=false
for argument in "$@"; do
  case "$argument" in
    --require-signature) require_signature=true ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; fail "unknown option: $argument" ;;
  esac
done

download() {
  source_url=$1
  destination=$2
  case "$source_url" in
    http://*|https://*|file://*)
      if command -v curl >/dev/null 2>&1; then
        curl --fail --location --silent --show-error "$source_url" --output "$destination"
      elif command -v wget >/dev/null 2>&1; then
        wget -q "$source_url" -O "$destination"
      else
        fail "curl or wget is required"
      fi
      ;;
    *) cp "$source_url" "$destination" ;;
  esac
}

os_name=$(uname -s)
case "$os_name" in
  Darwin) target_os=darwin ;;
  Linux) target_os=linux ;;
  *) fail "unsupported operating system: $os_name" ;;
esac

arch_name=$(uname -m)
case "$arch_name" in
  x86_64|amd64) target_arch=amd64 ;;
  arm64|aarch64) target_arch=arm64 ;;
  *) fail "unsupported architecture: $arch_name" ;;
esac

work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT HUP INT TERM

# newest_version_tag prints the first tag in a GitHub release list that is a
# version, v followed by a digit. The list is newest first. Other releases,
# such as the one that hosts this installer, are never chosen.
newest_version_tag() {
  grep -o '"tag_name"[[:space:]]*:[[:space:]]*"[^"]*"' "$1" |
    sed 's/.*"\([^"]*\)"$/\1/' |
    grep '^v[0-9]' |
    head -n 1
}

tag=${TFPREFLIGHT_VERSION:-}
if [ -z "$tag" ]; then
  release_json="$work_dir/releases.json"
  # The release list, not /releases/latest: the choice then never depends on
  # which release GitHub marks latest, and the pack and installer releases in
  # the list are skipped by their tags.
  download "${TFPREFLIGHT_RELEASES_URL:-https://api.github.com/repos/$repository/releases?per_page=100}" "$release_json"
  tag=$(newest_version_tag "$release_json" || true)
  [ -n "$tag" ] || fail "could not determine the latest release tag; set TFPREFLIGHT_VERSION"
fi

version=${tag#v}
archive="tfpreflight_${version}_${target_os}_${target_arch}.tar.gz"
checksums="tfpreflight_${version}_checksums.txt"

if [ -n "${TFPREFLIGHT_RELEASE_BASE_URL:-}" ]; then
  base=${TFPREFLIGHT_RELEASE_BASE_URL%/}
else
  base="https://github.com/$repository/releases/download/$tag"
fi

download "$base/$archive" "$work_dir/$archive"
download "$base/$checksums" "$work_dir/$checksums"
download "$base/$checksums.sigstore.json" "$work_dir/$checksums.sigstore.json" ||
  fail "could not download $checksums.sigstore.json, the checksum file's signature"

# The checksums are trusted only after their signature verifies: a party
# able to replace the archive could replace an unsigned checksum file too.
if command -v cosign >/dev/null 2>&1; then
  if ! cosign verify-blob \
    --certificate-identity-regexp "$certificate_identity_regexp" \
    --certificate-oidc-issuer "$certificate_oidc_issuer" \
    --bundle "$work_dir/$checksums.sigstore.json" \
    "$work_dir/$checksums" >"$work_dir/cosign.log" 2>&1; then
    cat "$work_dir/cosign.log" >&2
    fail "the signature on $checksums did not verify; nothing was installed"
  fi
  signature_checked=true
elif [ "$require_signature" = true ]; then
  fail "cosign is required by --require-signature but is not installed; see https://docs.sigstore.dev/cosign/system_config/installation/"
else
  signature_checked=false
  warn "cosign is not installed, so the signature on $checksums was NOT checked."
  warn "Only the archive's SHA-256 against that unsigned checksum file is verified."
  warn "To check the signature, install cosign and rerun with --require-signature,"
  warn "or follow https://github.com/$repository/blob/main/docs/install.md#verify-the-signature-yourself"
fi

expected=$(awk -v name="$archive" '$2 == name || $2 == "*" name { print $1; exit }' "$work_dir/$checksums")
[ -n "$expected" ] || fail "$archive is not listed in $checksums"
if command -v sha256sum >/dev/null 2>&1; then
  actual=$(sha256sum "$work_dir/$archive" | awk '{print $1}')
elif command -v shasum >/dev/null 2>&1; then
  actual=$(shasum -a 256 "$work_dir/$archive" | awk '{print $1}')
else
  fail "sha256sum or shasum is required"
fi
[ "$actual" = "$expected" ] || fail "checksum verification failed for $archive"

tar -xzf "$work_dir/$archive" -C "$work_dir"
[ -f "$work_dir/tfpreflight" ] || fail "$archive does not contain tfpreflight"

install_dir=${TFPREFLIGHT_INSTALL_DIR:-}
if [ -z "$install_dir" ]; then
  if [ -d /usr/local/bin ] && [ -w /usr/local/bin ]; then
    install_dir=/usr/local/bin
  else
    install_dir="$HOME/.local/bin"
  fi
fi

mkdir -p "$install_dir" || fail "cannot create $install_dir; choose a writable directory with TFPREFLIGHT_INSTALL_DIR"
[ -w "$install_dir" ] || fail "$install_dir is not writable; choose another directory or rerun the command yourself with the privileges you intend"
install -m 0755 "$work_dir/tfpreflight" "$install_dir/tfpreflight"

# tfp is a short name for the same program: a link, not a second copy. It is
# made only when it would not hide or replace another tfp.
shortcut="$install_dir/tfp"
other_tfp=$(command -v tfp 2>/dev/null || true)
if [ -n "$other_tfp" ] && [ "$other_tfp" != "$shortcut" ]; then
  shortcut_note="Skipped the tfp shortcut: $other_tfp is already on PATH."
elif { [ -e "$shortcut" ] || [ -L "$shortcut" ]; } && [ "$(readlink "$shortcut" 2>/dev/null)" != tfpreflight ]; then
  shortcut_note="Skipped the tfp shortcut: $shortcut already exists."
else
  ln -sf tfpreflight "$shortcut"
  shortcut_note="Also available as tfp."
fi

if [ "$signature_checked" = true ]; then
  printf 'Installed tfpreflight %s to %s/tfpreflight (signature and checksum verified)\n' "$version" "$install_dir"
else
  printf 'Installed tfpreflight %s to %s/tfpreflight (checksum verified; signature not checked)\n' "$version" "$install_dir"
fi
printf '%s\n' "$shortcut_note"
case ":$PATH:" in
  *":$install_dir:"*) ;;
  *) printf 'Add %s to PATH before running tfpreflight.\n' "$install_dir" ;;
esac
