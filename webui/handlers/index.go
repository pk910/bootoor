package handlers

import (
	"net/http"

	"github.com/ethpandaops/bootnodoor/webui/server"
)

type IndexPage struct {
}

// Index will return the "index" page using a go template
func (fh *FrontendHandler) Index(w http.ResponseWriter, r *http.Request) {
	templateFiles := server.LayoutTemplateFiles
	templateFiles = append(templateFiles, "index/index.html")
	pageTemplate := server.GetTemplate(templateFiles...)
	data := server.InitPageData(r, "index", "/", "Index", templateFiles)

	var pageError error

	data.Data, pageError = fh.getIndexPageData()
	if pageError != nil {
		server.HandlePageError(w, r, pageError)
		return
	}

	w.Header().Set("Content-Type", "text/html")

	if server.HandleTemplateError(w, r, "index.go", "Index", "", pageTemplate.ExecuteTemplate(w, "layout", data)) != nil {
		return // an error has occurred and was processed
	}
}

func (fh *FrontendHandler) getIndexPageData() (*IndexPage, error) {
	pageData := &IndexPage{}

	return pageData, nil
}
