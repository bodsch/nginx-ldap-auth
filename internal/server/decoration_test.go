package server

import (
	"bytes"
	"encoding/base64"
	"image/png"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

// maskURI finds the two custom properties in the rendered page and captures the
// media type and the payload of each.
var maskURI = regexp.MustCompile(`(--login-(?:emblem|skyline)-mask): url\(data:([a-z+/]+);base64,([A-Za-z0-9+/=]+)\)`)

// TestLoginPageCarriesItsDecoration renders the built-in form and decodes what
// arrives in the browser.
//
// Nothing else notices when the decoration is lost. html/template replaces a
// value it will not put into a stylesheet with "ZgotmplZ" and renders on; an
// empty or truncated embed renders as well; and a CSP without img-src data:
// makes the browser drop both masks with a console message nobody reads. In
// each case the form still works and every other test stays green.
func TestLoginPageCarriesItsDecoration(t *testing.T) {
	ts := sessionServer(t, sessionConfig())

	rec := httptest.NewRecorder()
	ts.handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/login", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /login = %d, want 200", rec.Code)
	}

	body := rec.Body.String()
	if strings.Contains(body, "ZgotmplZ") {
		t.Fatal("html/template refused a value in the page; the decoration is not in it")
	}

	found := map[string]bool{}

	for _, m := range maskURI.FindAllStringSubmatch(body, -1) {
		property, mediaType, payload := m[1], m[2], m[3]
		found[property] = true

		data, err := base64.StdEncoding.DecodeString(payload)
		if err != nil {
			t.Errorf("%s is not valid base64: %v", property, err)

			continue
		}

		switch mediaType {
		case "image/png":
			if _, err := png.DecodeConfig(bytes.NewReader(data)); err != nil {
				t.Errorf("%s does not decode as a PNG: %v", property, err)
			}
		case "image/svg+xml":
			if !bytes.Contains(data, []byte("<svg")) || !bytes.Contains(data, []byte("</svg>")) {
				t.Errorf("%s is not a complete SVG document", property)
			}
		default:
			t.Errorf("%s has media type %q", property, mediaType)
		}
	}

	for _, property := range []string{"--login-emblem-mask", "--login-skyline-mask"} {
		if !found[property] {
			t.Errorf("the page declares no %s", property)
		}

		if !strings.Contains(body, "var("+property+")") {
			t.Errorf("the page declares %s but no rule uses it", property)
		}
	}

	// The masks are images as far as the CSP is concerned. data: is the one
	// source they need, and the only one the policy may name: anything else
	// would be the first thing this page loads from elsewhere.
	csp := rec.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "img-src data:;") {
		t.Errorf("Content-Security-Policy = %q, want img-src data: and nothing more", csp)
	}
}
