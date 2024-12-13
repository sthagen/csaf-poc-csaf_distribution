// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2023 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2023 Intevation GmbH <https://intevation.de>

// Package testutil contains shared helper functions for testing the application.
package testutil

import (
	"html/template"
	"net/http"
	"os"
	"strings"
)

// ProviderParams configures the test provider.
type ProviderParams struct {
	URL                string
	EnableSha256       bool
	EnableSha512       bool
	ForbidHashFetching bool
}

// ProviderHandler returns a test provider handler with the specified configuration.
func ProviderHandler(params *ProviderParams, directoryProvider bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		path := "../../testdata/"
		if directoryProvider {
			path += "simple-directory-provider"
		} else {
			path += "simple-rolie-provider"
		}

		path += r.URL.Path

		if strings.HasSuffix(r.URL.Path, "/") {
			path += "index.html"
		}

		content, err := os.ReadFile(path)
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		switch {
		case strings.HasSuffix(path, ".html"):
			w.Header().Add("Content-Type", "text/html")
		case strings.HasSuffix(path, ".json"):
			w.Header().Add("Content-Type", "application/json")
		case (strings.HasSuffix(path, ".sha256") || strings.HasSuffix(path, ".sha512")) && params.ForbidHashFetching:
			w.WriteHeader(http.StatusForbidden)
			return
		case strings.HasSuffix(path, ".sha256") && directoryProvider && !params.EnableSha256:
			w.WriteHeader(http.StatusNotFound)
			return
		case strings.HasSuffix(path, ".sha512") && directoryProvider && !params.EnableSha512:
			w.WriteHeader(http.StatusNotFound)
			return
		default:
			w.Header().Add("Content-Type", "text/plain")
		}

		tmplt, err := template.New("base").Parse(string(content))
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		err = tmplt.Execute(w, params)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}
}
