# Installing tfpreflight

> **In short:** on a Mac or Linux, run one of these. That's it.
>
> ```sh
> brew install tfpreflight/tap/tfpreflight
> ```
> ```sh
> curl -fsSL https://get.tfpreflight.dev/install.sh | sh
> ```

## Homebrew

```sh
brew install tfpreflight/tap/tfpreflight
```

`brew upgrade tfpreflight` gets new versions later.

## Install script

```sh
curl -fsSL https://get.tfpreflight.dev/install.sh | sh
```

What it does:

1. Picks the right download for your system (Mac or Linux, Intel or ARM).
2. Downloads it and checks it wasn't changed on the way.
3. Puts `tfpreflight` in `/usr/local/bin`, or in `~/.local/bin` if it can't write there. It never uses `sudo`.

### Extra safety: require a signature check

Every release is signed by this project's release robot. If you have [cosign](https://docs.sigstore.dev/cosign/system_config/installation/) installed (a free tool that checks those signatures), the script checks the signature automatically. Without cosign, it only checks the download's checksum, and prints a warning.

To refuse to install unless the signature checks out:

```sh
curl -fsSL https://get.tfpreflight.dev/install.sh | sh -s -- --require-signature
```

### Options

Install somewhere else:

```sh
curl -fsSL https://get.tfpreflight.dev/install.sh | TFPREFLIGHT_INSTALL_DIR="$HOME/bin" sh
```

Install a specific version (by default you get the newest, including betas):

```sh
curl -fsSL https://get.tfpreflight.dev/install.sh | TFPREFLIGHT_VERSION=v0.1.0-beta.1 sh
```

## Manual install (including Windows)

1. From the [GitHub releases page](https://github.com/tfpreflight/tfpreflight/releases), download three files:
   - the archive for your system
   - `tfpreflight_<version>_checksums.txt`
   - `tfpreflight_<version>_checksums.txt.sigstore.json`
2. Check the signature (optional, needs cosign). See [Verify the signature yourself](#verify-the-signature-yourself) below.
3. Check the archive wasn't changed:
   - Mac: `shasum -a 256 -c --ignore-missing tfpreflight_<version>_checksums.txt`
   - Linux: `sha256sum -c --ignore-missing tfpreflight_<version>_checksums.txt`
4. Unzip it and move `tfpreflight` (or `tfpreflight.exe` on Windows) into a folder on your `PATH`.

## Verify the signature yourself

Every release's checksum file is signed by this project's release workflow. With [cosign](https://docs.sigstore.dev/cosign/system_config/installation/) installed, run this in the folder with the two files:

```sh
cosign verify-blob \
  --certificate-identity-regexp '^https://github.com/tfpreflight/tfpreflight/.github/workflows/release.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --bundle tfpreflight_<version>_checksums.txt.sigstore.json \
  tfpreflight_<version>_checksums.txt
```

It prints `Verified OK` when the signature is good. Then check your archive against the checksum file, as in step 3 above.