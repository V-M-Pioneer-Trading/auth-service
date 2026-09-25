package api

// Conformance against meta/fixtures/introspection.json, vendored verbatim into
// testdata/ (provenance in testdata/SOURCE.txt).
//
// The fixture's `cases` and `gatewayCases` describe what a CALLING SERVICE
// answers its own caller, which auth-service does not implement — it is the
// center. What binds this repository is:
//
//   - the `contract` block: the path, method, content type, body template, the
//     secret header's spelling and the env var names; and
//   - every `center` object inside every case: those bodies are literally this
//     service's own output, and a client's whole suite is built on the
//     assumption that the center really does produce them.
//
// So this test walks EVERY case in both groups and drives the real route with
// a real signed token for each center response it is possible for the center
// to produce, asserting the status and structurally equal JSON (same keys,
// same values; order and whitespace ignored). Cases whose `center` describes client-
// side transport (a delay, a dead socket, a 500, an HTML body) are not skipped
// silently: they are classified, counted, and the classification itself is
// asserted, so a case added to meta that this file does not understand fails
// the run instead of quietly checking less.

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

type fixtureFile struct {
	Version  int `json:"version"`
	Contract struct {
		Endpoint struct {
			Method       string `json:"method"`
			Path         string `json:"path"`
			ContentType  string `json:"contentType"`
			BodyTemplate string `json:"bodyTemplate"`
			SecretHeader string `json:"secretHeader"`
		} `json:"endpoint"`
		Env struct {
			URL    string `json:"url"`
			Secret string `json:"secret"`
		} `json:"env"`
	} `json:"contract"`
	Cases        []fixtureCase `json:"cases"`
	GatewayCases []fixtureCase `json:"gatewayCases"`
}

type fixtureCase struct {
	Name   string `json:"name"`
	Center struct {
		NotCalled bool   `json:"notCalled"`
		Status    int    `json:"status"`
		Body      string `json:"body"`
		DelayMs   int    `json:"delayMs"`
		Transport string `json:"transport"`
	} `json:"center"`
}

// centerBody is the contract's own response shape, decoded from a fixture
// `center.body` so it can be compared against what the route really writes.
type centerBody struct {
	Active bool   `json:"active"`
	Sub    string `json:"sub"`
	Scope  string `json:"scope"`
	Exp    int64  `json:"exp"`
	Kind   string `json:"kind"`
}

func loadFixture(t *testing.T) fixtureFile {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "introspection.json"))
	if err != nil {
		t.Fatalf("the vendored fixture is missing (see testdata/SOURCE.txt): %v", err)
	}
	var f fixtureFile
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("the vendored fixture does not parse: %v", err)
	}
	if f.Version != 1 {
		t.Fatalf("vendored fixture is version %d; this test was written against version 1 — re-read it before re-copying", f.Version)
	}
	return f
}

// TestFixtureContractNamesMatchTheRoute pins every name three
// implementations have to agree on. A rename in meta breaks this before it
// breaks production.
func TestFixtureContractNamesMatchTheRoute(t *testing.T) {
	f := loadFixture(t)
	e := f.Contract.Endpoint

	if e.Method != "POST" {
		t.Errorf("fixture method is %q; the route is mounted POST-only", e.Method)
	}
	if e.SecretHeader != IntrospectionSecretHeader {
		t.Errorf("fixture secret header is %q, code uses %q", e.SecretHeader, IntrospectionSecretHeader)
	}
	if e.ContentType != "application/x-www-form-urlencoded" {
		t.Errorf("unexpected fixture content type %q", e.ContentType)
	}
	if e.BodyTemplate != "token=<jwt>" {
		t.Errorf("unexpected fixture body template %q", e.BodyTemplate)
	}
	if f.Contract.Env.Secret != "AUTH_INTROSPECTION_SECRET" {
		t.Errorf("fixture names the secret env var %q; ReadIntrospectionSecret reads AUTH_INTROSPECTION_SECRET", f.Contract.Env.Secret)
	}

	// The path is asserted by using it: a router that does not serve the
	// fixture's path answers 404 here.
	router, _, _ := newTestRouter(t)
	valid := signTestToken(testPrivateKey, testTokenOptions{scopes: []string{SCOPEAgentReset}})
	form := url.Values{}
	form.Set("token", valid)
	rec := introspectRaw(t, router, e.Path, form.Encode(), testIntrospectionSecret, true)
	if body := decodeIntrospection(t, rec); body["active"] != true {
		t.Fatalf("the fixture's path %q did not answer an active token: %d %s", e.Path, rec.Code, rec.Body.String())
	}
}

// classify says what a fixture case's `center` object means for the CENTER's
// own test, and is itself asserted below so an unclassifiable case fails.
type centerClass int

const (
	classNotApplicable centerClass = iota // the center is not called at all
	classActive                           // a 200 the center produces for a good token
	classInactive                         // the 200 {"active":false}
	classCallerSecret                     // the 401 about OUR caller secret
	classClientOnly                       // transport/5xx/garbage: a stub's job, not the center's
)

func classify(c fixtureCase) (centerClass, *centerBody) {
	switch {
	case c.Center.NotCalled:
		return classNotApplicable, nil
	case c.Center.Transport != "" || c.Center.DelayMs > 0:
		return classClientOnly, nil
	case c.Center.Status == 401:
		return classCallerSecret, nil
	case c.Center.Status != 200:
		return classClientOnly, nil
	}
	var body centerBody
	if err := json.Unmarshal([]byte(c.Center.Body), &body); err != nil {
		// A 200 whose body is not the contract (the malformed-JSON case).
		return classClientOnly, nil
	}
	if !body.Active {
		return classInactive, nil
	}
	return classActive, &body
}

// TestCenterProducesEveryFixtureResponse is the conformance pass. Every case
// in both groups is visited; none is skipped without being accounted for.
func TestCenterProducesEveryFixtureResponse(t *testing.T) {
	f := loadFixture(t)
	router, _, _ := newTestRouter(t)

	all := append(append([]fixtureCase{}, f.Cases...), f.GatewayCases...)
	if len(all) != 33 {
		t.Fatalf("expected 33 fixture cases (24 calling-service + 9 gateway), found %d — re-read meta before re-copying", len(all))
	}

	counts := map[centerClass]int{}

	for _, c := range all {
		class, want := classify(c)
		counts[class]++

		switch class {
		case classNotApplicable, classClientOnly:
			// Nothing for the center to produce. Counted, and the totals are
			// asserted below so this branch cannot quietly swallow a case that
			// should have exercised the route.

		case classInactive:
			t.Run(c.Name+"/inactive", func(t *testing.T) {
				// The fixture's token strings are deliberately not JWTs. Send
				// one verbatim: the center must answer exactly this body.
				rec := introspect(t, router, "expired.token.one", testIntrospectionSecret, true)
				if rec.Code != c.Center.Status {
					t.Fatalf("got %d, fixture says the center answers %d", rec.Code, c.Center.Status)
				}
				assertBodyEquals(t, rec.Body.String(), c.Center.Body)
			})

		case classCallerSecret:
			t.Run(c.Name+"/caller-secret", func(t *testing.T) {
				rec := introspect(t, router, "anything", "the-wrong-secret", true)
				if rec.Code != c.Center.Status {
					t.Fatalf("got %d, fixture says the center answers %d", rec.Code, c.Center.Status)
				}
				assertBodyEquals(t, rec.Body.String(), c.Center.Body)
			})

		case classActive:
			t.Run(c.Name+"/active", func(t *testing.T) {
				expected := *want
				// `kind` is derived by the center from the `sub` prefix, so the
				// two fixture cases that deliberately disagree with themselves
				// (kind-disagrees-with-sub-prefix and its gateway mirrors) are
				// unproducible HERE by construction. That is not a skip: the
				// assertion becomes "the center answers the DERIVED kind", which
				// is the very rule those cases exist to pin ownership of.
				derived := VerifiedToken{Subject: expected.Sub}.Kind()
				kindAgrees := expected.Kind == derived
				if !kindAgrees {
					t.Logf("fixture case %q reports kind %q for subject %q on purpose; "+
						"the center derives %q and cannot produce the pairing (that is the point of the case)",
						c.Name, expected.Kind, expected.Sub, derived)
					expected.Kind = derived
				}

				token := signTestToken(testPrivateKey, testTokenOptions{
					sub:           expected.Sub,
					scopeRaw:      expected.Scope,
					expiresAtUnix: expected.Exp,
				})
				rec := introspect(t, router, token, testIntrospectionSecret, true)
				if rec.Code != c.Center.Status {
					t.Fatalf("got %d, fixture says the center answers %d", rec.Code, c.Center.Status)
				}

				// Where the fixture's pairing is producible, compare against the
				// fixture's OWN body, never one re-marshalled through
				// introspectionResponse: marshalling the expectation through the
				// struct under test is how a `scope,omitempty` once dropped the
				// key from every scopeless answer with this test still green.
				if kindAgrees {
					assertBodyEquals(t, rec.Body.String(), c.Center.Body)
					return
				}
				wantJSON, err := json.Marshal(introspectionResponse{
					Active: true, Sub: expected.Sub, Scope: expected.Scope, Exp: expected.Exp, Kind: expected.Kind,
				})
				if err != nil {
					t.Fatal(err)
				}
				assertBodyEquals(t, rec.Body.String(), string(wantJSON))
			})
		}
	}

	// The classification is an assertion, not bookkeeping: if meta adds a case
	// whose center response this file does not understand, the totals move and
	// the run fails rather than checking less than it did yesterday.
	for class, want := range map[centerClass]int{
		classNotApplicable: 9, // the center is never called
		classActive:        12,
		classInactive:      4,
		classCallerSecret:  2,
		classClientOnly:    6, // transport failures, a 500, an HTML body
	} {
		if counts[class] != want {
			t.Errorf("class %d: found %d fixture cases, expected %d — a case was added, removed or changed in meta; "+
				"re-read fixtures/introspection.json and update testdata/SOURCE.txt", class, counts[class], want)
		}
	}
}

// TestVendoredFixtureIsTheExactCopyItClaimsToBe makes the vendored copy pin
// ITSELF. Counting cases was never enough: a case could be renamed, or its
// `center` body rewritten, or one swapped for another, and every count above
// would still add up. Two assertions close that.
//
// First the sha256 of the file against the value recorded in SOURCE.txt beside
// the meta commit — any byte that changes, anywhere in the fixture, fails here
// and names the file to re-read. The hash is over the file's LF bytes;
// .gitattributes marks this one file `-text` so a Windows checkout
// (core.autocrlf=true) holds the same bytes as a Linux one and the pin is not
// a CI-only pin.
//
// Second the sorted case names, which is the assertion that stays readable: a
// diff here says exactly which case meta added, dropped or renamed, where the
// hash only says "something moved".
func TestVendoredFixtureIsTheExactCopyItClaimsToBe(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "introspection.json"))
	if err != nil {
		t.Fatalf("the vendored fixture is missing (see testdata/SOURCE.txt): %v", err)
	}

	t.Run("sha256 matches the value recorded in SOURCE.txt", func(t *testing.T) {
		want := recordedFixtureSHA256(t)
		got := fmt.Sprintf("%x", sha256.Sum256(raw))
		if got != want {
			if bytes.Contains(raw, []byte("\r\n")) {
				t.Fatalf("the vendored fixture hashes to %s, SOURCE.txt records %s — the working copy has CRLF line endings, "+
					"so the `-text` entry in .gitattributes is missing or this file was checked out before it was added; "+
					"re-check it out (git rm --cached + git checkout) before re-recording the hash", got, want)
			}
			t.Fatalf("the vendored fixture hashes to %s, SOURCE.txt records %s — testdata/introspection.json and meta have drifted; "+
				"re-copy fixtures/introspection.json from meta and update BOTH the commit and the sha256 in testdata/SOURCE.txt", got, want)
		}
	})

	t.Run("the case names are exactly the ones this file was written against", func(t *testing.T) {
		f := loadFixture(t)
		got := make([]string, 0, len(f.Cases)+len(f.GatewayCases))
		for _, c := range append(append([]fixtureCase{}, f.Cases...), f.GatewayCases...) {
			got = append(got, c.Name)
		}
		sort.Strings(got)

		want := []string{
			"active-machine-kind",
			"active-with-irregular-scope-whitespace",
			"active-with-multi-value-scope",
			"active-with-required-scope",
			"active-without-required-scope",
			"center-rejects-our-caller-secret",
			"center-returns-500",
			"center-returns-malformed-json",
			"center-times-out",
			"center-unreachable",
			"gateway-active-machine",
			"gateway-active-operator",
			"gateway-center-rejects-our-caller-secret",
			"gateway-center-unreachable",
			"gateway-inactive-token",
			"gateway-kind-machine-with-user-subject",
			"gateway-kind-operator-with-machine-subject",
			"gateway-no-header",
			"gateway-non-bearer-scheme",
			"inactive-token-on-guarded-route",
			"inactive-token-on-public-get",
			"kind-disagrees-with-sub-prefix",
			"mutating-route-with-no-declared-scope",
			"mutating-route-with-no-declared-scope-and-inactive-token",
			"mutating-route-with-no-declared-scope-and-no-header",
			"no-header-on-guarded-route",
			"non-bearer-scheme-on-guarded-route",
			"operator-on-public-get",
			"session-route-with-inactive-token",
			"session-route-with-no-header",
			"session-route-with-scopeless-token",
			"token-on-public-get-while-center-is-down",
			"visitor-on-public-get",
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("the fixture's case names changed.\n got: %s\nwant: %s\n"+
				"re-read meta/fixtures/introspection.json, decide what the new or renamed case means for the CENTER, "+
				"then update this list, the class totals above and testdata/SOURCE.txt",
				strings.Join(got, "\n      "), strings.Join(want, "\n      "))
		}
	})
}

// recordedFixtureSHA256 reads the pin out of testdata/SOURCE.txt, so the
// provenance note and the assertion can never disagree with one another.
func recordedFixtureSHA256(t *testing.T) string {
	t.Helper()
	source, err := os.ReadFile(filepath.Join("testdata", "SOURCE.txt"))
	if err != nil {
		t.Fatalf("testdata/SOURCE.txt is missing: %v", err)
	}
	for _, line := range strings.Split(string(source), "\n") {
		_, value, found := strings.Cut(strings.TrimSpace(line), "sha256:")
		if !found {
			continue
		}
		hash := strings.TrimSpace(value)
		if len(hash) != 64 {
			t.Fatalf("testdata/SOURCE.txt records a malformed sha256 %q", hash)
		}
		return hash
	}
	t.Fatal("testdata/SOURCE.txt has no `sha256:` line — the vendored fixture's pin is what makes it a copy rather than a fork")
	return ""
}

// assertBodyEquals compares two JSON documents structurally, and additionally
// insists the answer carries no key the contract does not define.
func assertBodyEquals(t *testing.T, got, want string) {
	t.Helper()
	var gotDoc, wantDoc map[string]interface{}
	if err := json.Unmarshal([]byte(got), &gotDoc); err != nil {
		t.Fatalf("the route wrote a body that is not JSON (%v): %s", err, got)
	}
	if err := json.Unmarshal([]byte(want), &wantDoc); err != nil {
		t.Fatalf("the fixture body is not JSON (%v): %s", err, want)
	}
	if !reflect.DeepEqual(gotDoc, wantDoc) {
		t.Errorf("center response mismatch:\n got: %s\nwant: %s", strings.TrimSpace(got), want)
	}
}
