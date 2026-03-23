package dashboard

import "embed"

// StaticFS holds all files under internal/dashboard/static/
// (CSS, JS, and any other static assets).
//
//go:embed static
var StaticFS embed.FS

// TemplateFS holds all Go html/template files under internal/dashboard/templates/.
//
//go:embed templates
var TemplateFS embed.FS
