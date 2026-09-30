package server

import (
	_ "embed"
	"encoding/base64"
	"html/template"
)

// The login page decoration: an emblem above the form and a Hamburg harbour
// panorama along the bottom edge, the same two the webmailer and mail-monkey
// show on theirs.
//
// Both are inlined into the page as data: URIs rather than served from a path
// of their own. The login page fetches nothing (see loginTemplate), and a
// second path would also be a second nginx location every installation has to
// add — one that, forgotten, leaves the page bare with nothing in any log.
//
// watermark.png is an alpha-only palette image. The stylesheet uses it as a
// mask, so only its coverage matters, and 32 levels of alpha are
// indistinguishable at the opacity it is drawn with — at a third of the size of
// the full RGBA original, which counts here, because it is sent with every
// rendering of the form.
var (
	//go:embed assets/watermark.png
	emblemPNG []byte

	//go:embed assets/skyline-hamburg.svg
	skylineSVG []byte
)

// loginDecoration declares the two masks as custom properties, for the built-in
// template and for a replacement that wants the same decoration.
//
// It is built once: the files are part of the binary and cannot change while it
// runs.
//
//nolint:gosec // G203: the value is built from two files embedded at compile time and base64, whose alphabet cannot close url() or the rule
var loginDecoration = template.CSS(":root { " +
	"--login-emblem-mask: url(data:image/png;base64," + base64.StdEncoding.EncodeToString(emblemPNG) + "); " +
	"--login-skyline-mask: url(data:image/svg+xml;base64," + base64.StdEncoding.EncodeToString(skylineSVG) + "); }")
