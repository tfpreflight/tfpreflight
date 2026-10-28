package main

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tfpreflight/tfpreflight/internal/report"
)

// tfpreflight loads AWS credentials with the AWS SDK's default chain, as
// Terraform does. These tests give it each kind of profile and check whose
// credentials the run ended up using, and what it says when they cannot be had.

const (
	ssoAccessKey   = "ASIAEXAMPLESSOROLE00"
	ssoToken       = "example-sso-access-token"
	assumedKey     = "ASIAEXAMPLEASSUMED00"
	baseAccessKey  = "AKIAEXAMPLEBASEPROF0"
	processKey     = "AKIAEXAMPLEPROCESS00"
	exampleSecret  = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	ssoSessionName = "acme"
)

// stsCall is one request the fake STS answered: the action, and the access key
// it was signed with ("" for an unsigned request, such as a web identity login).
type stsCall struct{ Action, AccessKey string }

// credentialsSTS answers GetCallerIdentity, AssumeRole and
// AssumeRoleWithWebIdentity for placeholder accounts, and keeps what it was
// asked.
func credentialsSTS(t *testing.T) (url string, calls func() []stsCall) {
	t.Helper()
	var mu sync.Mutex
	var seen []stsCall
	credential := regexp.MustCompile(`Credential=([A-Z0-9]+)/`)
	credentials := `<Credentials><AccessKeyId>` + assumedKey + `</AccessKeyId><SecretAccessKey>` + exampleSecret +
		`</SecretAccessKey><SessionToken>example-session-token</SessionToken><Expiration>2099-01-01T00:00:00Z</Expiration></Credentials>`
	const namespace = ` xmlns="https://sts.amazonaws.com/doc/2011-06-15/"`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		call := stsCall{Action: r.PostForm.Get("Action")}
		if match := credential.FindStringSubmatch(r.Header.Get("Authorization")); match != nil {
			call.AccessKey = match[1]
		}
		mu.Lock()
		seen = append(seen, call)
		mu.Unlock()
		w.Header().Set("Content-Type", "text/xml")
		metadata := `<ResponseMetadata><RequestId>1</RequestId></ResponseMetadata>`
		switch call.Action {
		case "GetCallerIdentity":
			_, _ = io.WriteString(w, `<GetCallerIdentityResponse`+namespace+`><GetCallerIdentityResult><Arn>arn:aws:iam::123456789012:user/example</Arn>`+
				`<UserId>AIDAEXAMPLE</UserId><Account>123456789012</Account></GetCallerIdentityResult>`+metadata+`</GetCallerIdentityResponse>`)
		case "AssumeRole", "AssumeRoleWithWebIdentity":
			_, _ = io.WriteString(w, `<`+call.Action+`Response`+namespace+`><`+call.Action+`Result>`+credentials+
				`<AssumedRoleUser><AssumedRoleId>AROAEXAMPLE:session</AssumedRoleId><Arn>arn:aws:sts::999999999999:assumed-role/ops/session</Arn></AssumedRoleUser>`+
				`</`+call.Action+`Result>`+metadata+`</`+call.Action+`Response>`)
		default:
			http.Error(w, "unsupported", http.StatusBadRequest)
		}
	}))
	t.Cleanup(server.Close)
	return server.URL, func() []stsCall {
		mu.Lock()
		defer mu.Unlock()
		return append([]stsCall(nil), seen...)
	}
}

// ssoServices answers the SSO portal's GetRoleCredentials for the account and
// role in testdata/sso/config, and the OIDC service's CreateToken, and keeps
// the tokens the portal was asked with and the refresh tokens OIDC was given.
type ssoServices struct {
	mu       sync.Mutex
	portal   []string
	refreshs []string
}

func newSSOServices(t *testing.T) *ssoServices {
	t.Helper()
	s := &ssoServices{}
	portal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("x-amz-sso_bearer_token")
		s.mu.Lock()
		s.portal = append(s.portal, token)
		s.mu.Unlock()
		if r.URL.Path != "/federation/credentials" || r.URL.Query().Get("account_id") != "123456789012" || r.URL.Query().Get("role_name") != "ReadOnly" || token != ssoToken {
			http.Error(w, `{"message":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"roleCredentials": map[string]any{
			"accessKeyId": ssoAccessKey, "secretAccessKey": exampleSecret,
			"sessionToken": "example-session-token", "expiration": time.Now().Add(time.Hour).UnixMilli(),
		}})
	}))
	oidc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			RefreshToken string `json:"refreshToken"`
			GrantType    string `json:"grantType"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		s.mu.Lock()
		s.refreshs = append(s.refreshs, body.GrantType+":"+body.RefreshToken)
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"accessToken": ssoToken, "tokenType": "Bearer", "expiresIn": 3600, "refreshToken": "refresh-2"})
	}))
	t.Cleanup(portal.Close)
	t.Cleanup(oidc.Close)
	t.Setenv("AWS_ENDPOINT_URL_SSO", portal.URL)
	t.Setenv("AWS_ENDPOINT_URL_SSO_OIDC", oidc.URL)
	return s
}

func (s *ssoServices) portalTokens() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.portal...)
}

func (s *ssoServices) refreshes() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.refreshs...)
}

// ssoLogin writes the login `aws sso login` leaves for a session: a token file
// in ~/.aws/sso/cache, named after the session, in a new home directory.
func ssoLogin(t *testing.T, fields map[string]any) (home, tokenFile string) {
	t.Helper()
	home = t.TempDir()
	name := sha1.Sum([]byte(ssoSessionName))
	directory := filepath.Join(home, ".aws", "sso", "cache")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	tokenFile = filepath.Join(directory, hex.EncodeToString(name[:])+".json")
	if fields != nil {
		token, err := json.Marshal(fields)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(tokenFile, token, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return home, tokenFile
}

func validSSOToken() map[string]any {
	return map[string]any{"accessToken": ssoToken, "expiresAt": time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}
}

// refreshableSSOToken is a login whose access token has run out but which holds
// what is needed to get a new one, as `aws sso login` leaves it after an hour.
func refreshableSSOToken() map[string]any {
	return map[string]any{
		"accessToken": "stale-token", "expiresAt": time.Now().Add(-time.Hour).UTC().Format(time.RFC3339),
		"refreshToken": "refresh-1", "clientId": "client-id", "clientSecret": "client-secret",
		"registrationExpiresAt": time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339),
	}
}

// inPlanDir makes a fixture's folder the working directory, with the AWS SDK
// given nothing but the config file at configPath and the home directory, and
// every call but STS and SSO refused.
func inPlanDir(t *testing.T, fixture, configPath, home string) {
	t.Helper()
	dir, err := filepath.Abs(filepath.Join("testdata", fixture))
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	isolateAWS(t, false)
	t.Setenv("AWS_CONFIG_FILE", configPath)
	t.Setenv("HOME", home)
	t.Setenv("AWS_ENDPOINT_URL", "http://127.0.0.1:1")
}

// ssoConfigPath is the AWS config that signs in through an SSO session.
func ssoConfigPath(t *testing.T) string {
	t.Helper()
	path, err := filepath.Abs(filepath.Join("testdata", "sso", "config"))
	if err != nil {
		t.Fatal(err)
	}
	return path
}

// writeAWSConfig writes an AWS config file and returns its path.
func writeAWSConfig(t *testing.T, text string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// checkRan asserts the AWS checks ran: STS answered and the rest were refused.
func checkRan(t *testing.T, document report.Document) {
	t.Helper()
	if !strings.HasPrefix(document.Summary.Verdict, "PARTIAL - AWS checks failed: ") {
		t.Fatalf("the AWS checks did not run: %q", document.Summary.Verdict)
	}
}

func lastCall(t *testing.T, calls []stsCall, action string) stsCall {
	t.Helper()
	for i := len(calls) - 1; i >= 0; i-- {
		if calls[i].Action == action {
			return calls[i]
		}
	}
	t.Fatalf("STS was never sent %s: %+v", action, calls)
	return stsCall{}
}

// A profile that signs in through SSO, selected with AWS_PROFILE, as in
// ~/.aws/config after `aws configure sso`.
func TestSSOProfileSelectedByTheEnvironment(t *testing.T) {
	config := ssoConfigPath(t)
	home, _ := ssoLogin(t, validSSOToken())
	inPlanDir(t, "realworld/vpc-simple", config, home)
	t.Setenv("AWS_PROFILE", "dev-sso")
	sso := newSSOServices(t)
	stsURL, calls := credentialsSTS(t)
	t.Setenv("AWS_ENDPOINT_URL_STS", stsURL)

	_, _, document := runRealWorldCheck(t)

	checkRan(t, document)
	if got := lastCall(t, calls(), "GetCallerIdentity").AccessKey; got != ssoAccessKey {
		t.Errorf("the account was confirmed with access key %q, want the SSO role's %q", got, ssoAccessKey)
	}
	if tokens := sso.portalTokens(); len(tokens) == 0 || tokens[0] != ssoToken {
		t.Errorf("the SSO portal was asked with %v, want the cached login %q", tokens, ssoToken)
	}
}

// The same profile named by the provider block, as a variable.
func TestSSOProfileNamedByTheProvider(t *testing.T) {
	config := writeAWSConfig(t, strings.ReplaceAll(readFile(t, ssoConfigPath(t)), "dev-sso", "example"))
	home, _ := ssoLogin(t, validSSOToken())
	inPlanDir(t, "profile-variable", config, home)
	newSSOServices(t)
	stsURL, calls := credentialsSTS(t)
	t.Setenv("AWS_ENDPOINT_URL_STS", stsURL)

	_, _, document := runRealWorldCheck(t)

	checkRan(t, document)
	if got := lastCall(t, calls(), "GetCallerIdentity").AccessKey; got != ssoAccessKey {
		t.Errorf("the account was confirmed with access key %q, want the SSO role's %q", got, ssoAccessKey)
	}
}

// An hour after `aws sso login` the access token has run out, but the login
// holds a refresh token. The SDK gets a new access token, and keeps it.
func TestSSOLoginIsRefreshed(t *testing.T) {
	home, tokenFile := ssoLogin(t, refreshableSSOToken())
	inPlanDir(t, "realworld/vpc-simple", ssoConfigPath(t), home)
	t.Setenv("AWS_PROFILE", "dev-sso")
	sso := newSSOServices(t)
	stsURL, calls := credentialsSTS(t)
	t.Setenv("AWS_ENDPOINT_URL_STS", stsURL)

	_, _, document := runRealWorldCheck(t)

	checkRan(t, document)
	if got := sso.refreshes(); len(got) == 0 || got[0] != "refresh_token:refresh-1" {
		t.Errorf("the login was refreshed with %v, want the refresh token", got)
	}
	if got := lastCall(t, calls(), "GetCallerIdentity").AccessKey; got != ssoAccessKey {
		t.Errorf("the account was confirmed with access key %q, want the SSO role's %q", got, ssoAccessKey)
	}
	if saved := readFile(t, tokenFile); !strings.Contains(saved, ssoToken) {
		t.Errorf("the refreshed token was not kept in %s: %s", tokenFile, saved)
	}
}

// A login that has run out and cannot be refreshed, or was never done, is said
// to be that, with the command that fixes it, not "no credentials".
func TestSSOLoginNeeded(t *testing.T) {
	expired := validSSOToken()
	expired["expiresAt"] = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	for name, token := range map[string]map[string]any{"expired": expired, "never done": nil} {
		t.Run(name, func(t *testing.T) {
			home, _ := ssoLogin(t, token)
			inPlanDir(t, "realworld/vpc-simple", ssoConfigPath(t), home)
			t.Setenv("AWS_PROFILE", "dev-sso")
			sso := newSSOServices(t)

			summary, _, document := runRealWorldCheck(t)

			const reason = `AWS profile "dev-sso" (from AWS_PROFILE) has no usable credentials: the SSO login has expired or was never done; run: aws sso login --profile dev-sso`
			if !strings.HasPrefix(document.Summary.Verdict, "PARTIAL - AWS checks did not run: "+reason) {
				t.Errorf("verdict %q does not say %q", document.Summary.Verdict, reason)
			}
			if !strings.Contains(summary, "! AWS checks did not run: "+reason) {
				t.Errorf("default output does not say %q:\n%s", reason, summary)
			}
			if tokens := sso.portalTokens(); len(tokens) != 0 {
				t.Errorf("the portal was asked although there was no login: %v", tokens)
			}
		})
	}
}

// A good login with the portal out of reach is not an expired login, and is not
// called one.
func TestSSOPortalUnreachableIsNotAnExpiredLogin(t *testing.T) {
	home, _ := ssoLogin(t, validSSOToken())
	inPlanDir(t, "realworld/vpc-simple", ssoConfigPath(t), home)
	t.Setenv("AWS_PROFILE", "dev-sso")
	t.Setenv("AWS_ENDPOINT_URL_SSO", "http://127.0.0.1:1")

	_, details, document := runRealWorldCheck(t)

	const prefix = `PARTIAL - AWS checks did not run: AWS profile "dev-sso" (from AWS_PROFILE) has no usable credentials: `
	if !strings.HasPrefix(document.Summary.Verdict, prefix) || strings.Contains(document.Summary.Verdict, "aws sso login") {
		t.Errorf("verdict %q", document.Summary.Verdict)
	}
	if !strings.Contains(details, "GetRoleCredentials") {
		t.Errorf("the SDK's reason is missing:\n%s", details)
	}
}

// credential_process: the SDK runs the command and uses what it prints.
func TestCredentialProcessProfile(t *testing.T) {
	process := `echo '{"Version":1,"AccessKeyId":"` + processKey + `","SecretAccessKey":"` + exampleSecret + `"}'`
	config := writeAWSConfig(t, "[profile proc]\nregion = eu-west-1\ncredential_process = "+process+"\n")
	inPlanDir(t, "realworld/vpc-simple", config, t.TempDir())
	t.Setenv("AWS_PROFILE", "proc")
	stsURL, calls := credentialsSTS(t)
	t.Setenv("AWS_ENDPOINT_URL_STS", stsURL)

	_, _, document := runRealWorldCheck(t)

	checkRan(t, document)
	if got := lastCall(t, calls(), "GetCallerIdentity").AccessKey; got != processKey {
		t.Errorf("the account was confirmed with access key %q, want the command's %q", got, processKey)
	}
}

// A profile that assumes a role with another profile's keys: STS is asked to
// assume the role with the base keys, and the run uses the role's.
func TestAssumeRoleProfile(t *testing.T) {
	config := writeAWSConfig(t, "[profile ops]\nregion = eu-west-1\nrole_arn = arn:aws:iam::999999999999:role/ops\nsource_profile = base\n\n"+
		"[profile base]\naws_access_key_id = "+baseAccessKey+"\naws_secret_access_key = "+exampleSecret+"\n")
	inPlanDir(t, "realworld/vpc-simple", config, t.TempDir())
	t.Setenv("AWS_PROFILE", "ops")
	stsURL, calls := credentialsSTS(t)
	t.Setenv("AWS_ENDPOINT_URL_STS", stsURL)

	_, _, document := runRealWorldCheck(t)

	checkRan(t, document)
	if got := lastCall(t, calls(), "AssumeRole").AccessKey; got != baseAccessKey {
		t.Errorf("the role was assumed with access key %q, want the base profile's %q", got, baseAccessKey)
	}
	if got := lastCall(t, calls(), "GetCallerIdentity").AccessKey; got != assumedKey {
		t.Errorf("the account was confirmed with access key %q, want the role's %q", got, assumedKey)
	}
}

// A profile that signs in with a web identity token, and the same from the
// environment, as CI systems set it up. The login itself is unsigned.
func TestWebIdentity(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte("example-web-identity-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, setup := range map[string]func(t *testing.T) string{
		"profile": func(t *testing.T) string {
			t.Setenv("AWS_PROFILE", "web")
			return "[profile web]\nregion = eu-west-1\nrole_arn = arn:aws:iam::999999999999:role/web\nweb_identity_token_file = " + tokenFile + "\n"
		},
		"environment": func(t *testing.T) string {
			t.Setenv("AWS_WEB_IDENTITY_TOKEN_FILE", tokenFile)
			t.Setenv("AWS_ROLE_ARN", "arn:aws:iam::999999999999:role/web")
			t.Setenv("AWS_REGION", "eu-west-1")
			return ""
		},
	} {
		t.Run(name, func(t *testing.T) {
			inPlanDir(t, "realworld/vpc-simple", filepath.Join(t.TempDir(), "absent"), t.TempDir())
			if config := setup(t); config != "" {
				t.Setenv("AWS_CONFIG_FILE", writeAWSConfig(t, config))
			}
			stsURL, calls := credentialsSTS(t)
			t.Setenv("AWS_ENDPOINT_URL_STS", stsURL)

			_, _, document := runRealWorldCheck(t)

			checkRan(t, document)
			if got := lastCall(t, calls(), "AssumeRoleWithWebIdentity").AccessKey; got != "" {
				t.Errorf("the web identity login was signed with %q, want it unsigned", got)
			}
			if got := lastCall(t, calls(), "GetCallerIdentity").AccessKey; got != assumedKey {
				t.Errorf("the account was confirmed with access key %q, want the role's %q", got, assumedKey)
			}
		})
	}
}

// AWS_PROFILE naming a profile the config does not have is said so, in the
// SDK's words, not as an unavailable configuration.
func TestProfileFromTheEnvironmentMissingFromTheConfig(t *testing.T) {
	inPlanDir(t, "realworld/vpc-simple", ssoConfigPath(t), t.TempDir())
	t.Setenv("AWS_PROFILE", "nonexistent")

	_, _, document := runRealWorldCheck(t)

	const prefix = `PARTIAL - AWS checks did not run: AWS profile "nonexistent" (from AWS_PROFILE) could not be loaded: `
	if !strings.HasPrefix(document.Summary.Verdict, prefix) || !strings.Contains(document.Summary.Verdict, "nonexistent") {
		t.Errorf("verdict %q does not start %q", document.Summary.Verdict, prefix)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
