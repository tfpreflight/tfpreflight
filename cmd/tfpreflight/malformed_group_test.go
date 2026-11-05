package main

import (
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The fake EC2 must answer as AWS does, or a test can pass on a value AWS would
// refuse. AWS's describe call calls malformedPeer malformed, though a create
// that names it gets InvalidGroup.NotFound.
func TestFakeEC2AnswersAsAWSDoes(t *testing.T) {
	ec2URL, _ := fakeEC2(t, absentPeer)
	for _, test := range []struct {
		id   string
		want string
	}{
		{malformedPeer, "InvalidGroupId.Malformed"},
		{"sg-123", "InvalidGroupId.Malformed"},
		{"not-an-id", "InvalidGroupId.Malformed"},
		{absentPeer, "InvalidGroup.NotFound"},
		{ownGroup, ""},
	} {
		response, err := http.PostForm(ec2URL, url.Values{"Action": {"DescribeSecurityGroups"}, "GroupId.1": {test.id}})
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if test.want == "" {
			if response.StatusCode != http.StatusOK {
				t.Errorf("%s: status %d, want the group to exist", test.id, response.StatusCode)
			}
			continue
		}
		if response.StatusCode != http.StatusBadRequest || !strings.Contains(string(body), "<Code>"+test.want+"</Code>") {
			t.Errorf("%s: %d %s, want %s", test.id, response.StatusCode, body, test.want)
		}
	}
}

// A group ID that has the shape of a real one and does not exist is a
// not-found answer, which keeps the peered VPC caveat: the group may be in a
// peered VPC or another account, which this lookup cannot see.
func TestSecurityGroupRuleWithAnAbsentPeerKeepsThePeeredVPCCaveat(t *testing.T) {
	copyFixtureWithPeer(t, "testdata/realworld-cases/sg-ingress-literal-peer", absentPeer)
	isolateAWS(t, true)
	t.Setenv("AWS_ENDPOINT_URL_STS", fakeSTS(t))
	ec2URL, asked := fakeEC2(t, absentPeer)
	t.Setenv("AWS_ENDPOINT_URL_EC2", ec2URL)
	summary, _, document := runRealWorldCheck(t)

	if !packsKnowThePeerRule(t) {
		t.Skip("the packs have no rule for the referenced security group yet")
	}
	assertNothingCheckedNeverPasses(t, summary, document)
	assertPeerWarning(t, summary, document, asked(), peerCase{
		id: absentPeer, title: "Referenced resource does not exist",
		wording: "AWS can't find security group " + absentPeer + " in this account and region; unless it is in a peered VPC or another account, apply will fail.",
	})
}

// copyFixtureWithPeer works in a copy of a case whose referenced group is peer,
// and changes into it.
func copyFixtureWithPeer(t *testing.T, from, peer string) {
	t.Helper()
	entries, err := os.ReadDir(from)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for _, entry := range entries {
		data, err := os.ReadFile(filepath.Join(from, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		data = []byte(strings.ReplaceAll(string(data), malformedPeer, peer))
		if err := os.WriteFile(filepath.Join(dir, entry.Name()), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	t.Chdir(dir)
}
