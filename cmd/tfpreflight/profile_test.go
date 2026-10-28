package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
)

const (
	profileAccessKey     = "AKIAEXAMPLEPROFILE00"
	environmentAccessKey = "AKIAEXAMPLEENVIRONM0"
)

// recordingSTS answers GetCallerIdentity for the placeholder account, as
// fakeSTS does, and keeps the access key each request was signed with.
func recordingSTS(t *testing.T) (url string, signedWith func() []string) {
	t.Helper()
	var mu sync.Mutex
	var keys []string
	credential := regexp.MustCompile(`Credential=([A-Z0-9]+)/`)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if match := credential.FindStringSubmatch(r.Header.Get("Authorization")); match != nil {
			mu.Lock()
			keys = append(keys, match[1])
			mu.Unlock()
		}
		if err := r.ParseForm(); err != nil || r.PostForm.Get("Action") != "GetCallerIdentity" {
			http.Error(w, "unsupported", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "text/xml")
		_, _ = io.WriteString(w, `<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetCallerIdentityResult>`+
			`<Arn>arn:aws:iam::123456789012:user/example</Arn><UserId>AIDAEXAMPLE</UserId><Account>123456789012</Account>`+
			`</GetCallerIdentityResult><ResponseMetadata><RequestId>1</RequestId></ResponseMetadata></GetCallerIdentityResponse>`)
	}))
	t.Cleanup(server.Close)
	return server.URL, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), keys...)
	}
}

// awsConfigWith writes a shared AWS config file holding the named profiles,
// each with its own access key, and points the SDK at it.
func awsConfigWith(t *testing.T, profiles map[string]string) {
	t.Helper()
	var config strings.Builder
	for name, key := range profiles {
		config.WriteString("[profile " + name + "]\nregion = eu-west-1\naws_access_key_id = " + key + "\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n\n")
	}
	path := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(path, []byte(config.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AWS_CONFIG_FILE", path)
}

// The plan of a provider block with profile = var.aws_profile, made by
// Terraform (testdata/profile-variable): the profile is read from the variable
// the plan records, and the AWS checks run with that profile's credentials,
// not the environment's. Before, the whole run was skipped as "provider profile
// is unresolved".
func TestProviderProfileFromAVariable(t *testing.T) {
	dir, err := filepath.Abs("testdata/profile-variable")
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	isolateAWS(t, true)
	t.Setenv("AWS_ACCESS_KEY_ID", environmentAccessKey)
	awsConfigWith(t, map[string]string{"example": profileAccessKey})
	stsURL, signedWith := recordingSTS(t)
	t.Setenv("AWS_ENDPOINT_URL_STS", stsURL)

	summary, details, document := runRealWorldCheck(t)

	// STS answered and every other call failed, so the checks ran and failed.
	assertHonestResult(t, details, document, "PARTIAL - AWS checks failed: ")
	assertShortResult(t, summary, document, "! AWS checks failed: ")
	if !strings.Contains(details, "\nRegion: eu-west-1 (from var.aws_region)\n") {
		t.Errorf("the region was not read from var.aws_region:\n%s", details)
	}
	keys := signedWith()
	if len(keys) == 0 {
		t.Fatal("STS was never asked who the credentials belong to")
	}
	for _, key := range keys {
		if key != profileAccessKey {
			t.Fatalf("STS was asked with access key %s, want the profile's %s (the environment's is %s)", key, profileAccessKey, environmentAccessKey)
		}
	}
}

// A profile the AWS config does not define is reported by name and where the
// run read it from, and nothing is checked in AWS.
func TestProviderProfileMissingFromTheAWSConfig(t *testing.T) {
	dir, err := filepath.Abs("testdata/profile-variable")
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	isolateAWS(t, true)
	awsConfigWith(t, map[string]string{"another": profileAccessKey})

	summary, details, document := runRealWorldCheck(t)

	const reason = `AWS profile "example" (from var.aws_profile) could not be loaded`
	if !strings.Contains(document.Summary.Verdict, "PARTIAL - AWS checks did not run: "+reason) {
		t.Errorf("verdict %q does not say %s", document.Summary.Verdict, reason)
	}
	if !strings.Contains(summary, "! AWS checks did not run: "+reason) {
		t.Errorf("default output does not say %s:\n%s", reason, summary)
	}
	if strings.Contains(details, "PASSED") || document.Summary.Blocking != 0 {
		t.Errorf("a run that checked nothing in AWS must not pass or block:\n%s", details)
	}
}
