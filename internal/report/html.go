package report

import (
	_ "embed"
	"html/template"
	"io"

	"github.com/Derposd/prosvet/internal/brand"
	"github.com/Derposd/prosvet/internal/model"
)

//go:embed report.html.tmpl
var reportTmpl string

var htmlTmpl = template.Must(template.New("report").Funcs(FuncMap()).Parse(reportTmpl))

// FuncMap returns the template helpers used by the report templates.
func FuncMap() template.FuncMap {
	return template.FuncMap{"kindStatus": KindStatus, "wlStatus": WhitelistStatus}
}

// Templates returns a clone of the report templates ("report" page and the
// reusable "report-body" fragment) for embedding in other pages.
func Templates() *template.Template {
	// A fresh parse instead of Clone: html/template cannot clone a template
	// set that has already been executed.
	return template.Must(template.New("report").Funcs(FuncMap()).Parse(reportTmpl))
}

// KindStatus maps a verdict kind to the status colour class used in HTML.
func KindStatus(k model.Kind) model.Status {
	switch {
	case k == model.KindOK:
		return model.StatusOK
	case k.IsThrottling():
		return model.StatusThrottled
	case k.IsProtocol():
		return model.StatusPartial
	case k.IsBlocking():
		return model.StatusBlocked
	}
	return model.StatusUnknown
}

// WhitelistStatus maps a whitelist verdict to a status colour class.
func WhitelistStatus(v string) model.Status {
	switch v {
	case model.WhitelistActive:
		return model.StatusBlocked
	case model.WhitelistDegraded:
		return model.StatusPartial
	case model.WhitelistNormal:
		return model.StatusOK
	}
	return model.StatusUnknown
}

// PageData is the data passed to the report templates.
type PageData struct {
	V       *View
	CSS     template.CSS
	Logo    template.HTML
	Favicon template.URL
	Token   string // dashboard only
	Running bool   // dashboard only
	Cats    []CatOption
}

// CatOption is a category checkbox on the dashboard.
type CatOption struct {
	ID      string
	Title   string
	Checked bool
	OptIn   bool
}

// NewPageData fills the static parts of PageData.
func NewPageData(v *View) PageData {
	return PageData{
		V:       v,
		CSS:     template.CSS(brand.CSS),                   //nolint:gosec // static, embedded stylesheet
		Logo:    template.HTML(brand.LogoWithID("report")), //nolint:gosec // static, embedded SVG
		Favicon: template.URL(brand.FaviconDataURI()),      //nolint:gosec // generated data: URI
	}
}

// WriteHTML renders a self-contained HTML report (no scripts, no external
// resources; the page sets a strict Content-Security-Policy).
func WriteHTML(w io.Writer, v *View) error {
	return htmlTmpl.ExecuteTemplate(w, "report", NewPageData(v))
}
