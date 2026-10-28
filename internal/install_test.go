package internal_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const installVersion = "9.9.9"

// installCase is one run of install.sh against a local release.
type installCase struct {
	name      string
	cosign    string // "verifies", "rejects", or "" for none on PATH
	args      []string
	release   func(dir string)
	installed bool
	stdout    string
	stderr    string
	// releases, when set, is the release list the installer chooses a
	// version from; otherwise TFPREFLIGHT_VERSION pins it.
	releases string
}

// The installer trusts the checksum file only after cosign verifies its
// signature with the release workflow's identity, warns when cosign is
// missing, and with --require-signature refuses to install without it.
func TestInstallerVerifiesTheSignedChecksums(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("install.sh supports macOS and Linux")
	}
	archive := "tfpreflight_" + installVersion + "_" + runtime.GOOS + "_" + runtime.GOARCH + ".tar.gz"
	for _, c := range []installCase{
		{name: "signature verifies", cosign: "verifies", installed: true, stdout: "(signature and checksum verified)"},
		{name: "signature rejected", cosign: "rejects", stderr: "the signature on tfpreflight_9.9.9_checksums.txt did not verify; nothing was installed"},
		{name: "no cosign", installed: true, stdout: "(checksum verified; signature not checked)", stderr: "signature on tfpreflight_9.9.9_checksums.txt was NOT checked"},
		{name: "no cosign, signature required", args: []string{"--require-signature"}, stderr: "cosign is required by --require-signature but is not installed"},
		{name: "signature verifies, required", cosign: "verifies", args: []string{"--require-signature"}, installed: true, stdout: "(signature and checksum verified)"},
		{name: "bundle missing", cosign: "verifies", release: removeFile("tfpreflight_9.9.9_checksums.txt.sigstore.json"), stderr: "could not download tfpreflight_9.9.9_checksums.txt.sigstore.json"},
		{name: "archive altered", cosign: "verifies", release: appendTo(archive), stderr: "checksum verification failed for " + archive},
		{name: "unknown option", args: []string{"--verify"}, stderr: "unknown option: --verify"},
	} {
		t.Run(c.name, func(t *testing.T) { runInstaller(t, c, archive) })
	}
}

// Without a pinned version the installer takes the newest release whose tag
// is a version, prereleases included, and never the release that hosts the
// installer itself, which is listed first after a release.
func TestInstallerChoosesTheNewestVersionTag(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("install.sh supports macOS and Linux")
	}
	archive := "tfpreflight_" + installVersion + "_" + runtime.GOOS + "_" + runtime.GOARCH + ".tar.gz"
	pretty := `[
  {
    "tag_name": "installer",
    "prerelease": false,
    "body": "Stable asset. Not \"tag_name\": \"v0.0.1\"."
  },
  {
    "tag_name": "v` + installVersion + `",
    "prerelease": true
  },
  {
    "tag_name": "v9.9.8",
    "prerelease": false
  }
]`
	compact := `[{"tag_name":"installer","prerelease":false},{"tag_name":"v` + installVersion + `","prerelease":true},{"tag_name":"v9.9.8"}]`
	for _, c := range []installCase{
		{name: "installer release listed first", releases: pretty, installed: true, stdout: "Installed tfpreflight " + installVersion},
		{name: "compact JSON", releases: compact, installed: true, stdout: "Installed tfpreflight " + installVersion},
		// The layout the release workflows make: the pack and installer
		// releases are pre-releases and the v* release is the latest.
		{name: "pack and installer pre-releases listed first", releases: `[{"tag_name":"packs-2026-10-28.1","prerelease":true},{"tag_name":"installer","prerelease":true},{"tag_name":"packs-index","prerelease":true},{"tag_name":"v` + installVersion + `","prerelease":false}]`, installed: true, stdout: "Installed tfpreflight " + installVersion},
		{name: "no version tag", releases: `[{"tag_name":"installer"},{"tag_name":"nightly"}]`, stderr: "could not determine the latest release tag; set TFPREFLIGHT_VERSION"},
		{name: "empty list", releases: `[]`, stderr: "could not determine the latest release tag"},
	} {
		t.Run(c.name, func(t *testing.T) { runInstaller(t, c, archive) })
	}
}

func runInstaller(t *testing.T, c installCase, archive string) {
	t.Helper()
	dir := t.TempDir()
	release, bin, target := filepath.Join(dir, "release"), filepath.Join(dir, "path"), filepath.Join(dir, "install")
	writeLocalRelease(t, release, archive)
	if c.release != nil {
		c.release(release)
	}
	cosignArgs := filepath.Join(dir, "cosign-args")
	writeFakeCosign(t, bin, c.cosign, cosignArgs)
	installer, err := filepath.Abs(filepath.Join(repoRoot, "install.sh"))
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command("/bin/sh", append([]string{installer}, c.args...)...)
	command.Env = []string{
		"PATH=" + bin + ":/usr/bin:/bin:/usr/sbin:/sbin", "HOME=" + dir,
		"TFPREFLIGHT_RELEASE_BASE_URL=" + release, "TFPREFLIGHT_INSTALL_DIR=" + target,
	}
	if c.releases == "" {
		command.Env = append(command.Env, "TFPREFLIGHT_VERSION=v"+installVersion)
	} else {
		list := filepath.Join(dir, "releases.json")
		if err := os.WriteFile(list, []byte(c.releases), 0o644); err != nil {
			t.Fatal(err)
		}
		command.Env = append(command.Env, "TFPREFLIGHT_RELEASES_URL="+list)
	}
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	err = command.Run()
	_, statErr := os.Stat(filepath.Join(target, "tfpreflight"))
	if (err == nil) != c.installed || (statErr == nil) != c.installed {
		t.Fatalf("exit error %v, installed %v; want installed %v\nstdout: %s\nstderr: %s", err, statErr == nil, c.installed, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), c.stdout) || !strings.Contains(stderr.String(), c.stderr) {
		t.Fatalf("stdout %q, stderr %q; want %q and %q", stdout.String(), stderr.String(), c.stdout, c.stderr)
	}
	assertCosignIdentity(t, c.cosign, cosignArgs)
}

// assertCosignIdentity checks cosign was asked to verify against the release
// workflow's certificate identity and GitHub's OIDC issuer.
func assertCosignIdentity(t *testing.T, cosign, argsFile string) {
	t.Helper()
	args, err := os.ReadFile(argsFile)
	if cosign == "" {
		if err == nil {
			t.Fatalf("cosign ran although none is on PATH: %s", args)
		}
		return
	}
	if err != nil {
		return // the run stopped before verification
	}
	for _, want := range []string{
		"verify-blob",
		"--certificate-identity-regexp ^https://github.com/tfpreflight/tfpreflight/.github/workflows/release.yml@refs/tags/v",
		"--certificate-oidc-issuer https://token.actions.githubusercontent.com",
		"tfpreflight_" + installVersion + "_checksums.txt.sigstore.json",
	} {
		if !strings.Contains(string(args), want) {
			t.Fatalf("cosign %s; want %q", args, want)
		}
	}
}

// writeLocalRelease writes a release in the published layout: the archive,
// its checksum file and the checksum file's signature bundle.
func writeLocalRelease(t *testing.T, dir, archive string) {
	t.Helper()
	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	tw := tar.NewWriter(gz)
	binary := []byte("#!/bin/sh\necho tfpreflight " + installVersion + "\n")
	if err := tw.WriteHeader(&tar.Header{Name: "tfpreflight", Mode: 0o755, Size: int64(len(binary))}); err != nil {
		t.Fatal(err)
	}
	_, _ = tw.Write(binary)
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(compressed.Bytes())
	checksums := "tfpreflight_" + installVersion + "_checksums.txt"
	files := map[string][]byte{
		archive:                      compressed.Bytes(),
		checksums:                    []byte(hex.EncodeToString(sum[:]) + "  " + archive + "\n"),
		checksums + ".sigstore.json": []byte(`{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"}`),
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), content, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// writeFakeCosign puts a cosign on PATH that records its arguments and
// verifies or rejects, or leaves PATH without one.
func writeFakeCosign(t *testing.T, bin, behaviour, argsFile string) {
	t.Helper()
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	if behaviour == "" {
		if path, err := exec.LookPath("cosign"); err == nil && (strings.HasPrefix(path, "/usr/") || strings.HasPrefix(path, "/bin/")) {
			t.Skip("a system cosign at " + path + " would be found")
		}
		return
	}
	exit := "0"
	if behaviour == "rejects" {
		exit = "1"
	}
	script := "#!/bin/sh\necho \"$@\" > '" + argsFile + "'\n[ " + exit + " = 0 ] || echo 'Error: none of the expected identities matched' >&2\nexit " + exit + "\n"
	if err := os.WriteFile(filepath.Join(bin, "cosign"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
}

func removeFile(name string) func(string) {
	return func(dir string) { _ = os.Remove(filepath.Join(dir, name)) }
}

func appendTo(name string) func(string) {
	return func(dir string) {
		file, err := os.OpenFile(filepath.Join(dir, name), os.O_APPEND|os.O_WRONLY, 0)
		if err == nil {
			_, _ = file.Write([]byte{0})
			_ = file.Close()
		}
	}
}
