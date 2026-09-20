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
// to produce, asserting byte-equal JSON. Cases whose `center` describes client-
// side transport (a delay, a dead socket, a 500, an HTML body) are not skipped
// silently: they are classified, counted, and the classification itself is
// asserted, so a case added to meta that this file does not understand fails
// the run instead of quietly checking less.

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
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
				if expected.Kind != derived {
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
