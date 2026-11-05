package web

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed static/*
var StaticFS embed.FS

func AssetHandler() http.Handler {
	sub, err := fs.Sub(StaticFS, "static")
	if err != nil {
		panic(err)
	}
	return http.FileServer(http.FS(sub))
}
