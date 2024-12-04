// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2023 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2023 Intevation GmbH <https://intevation.de>

package main

import (
	"fmt"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/gocsaf/csaf/v3/internal/testutil"
	"github.com/gocsaf/csaf/v3/util"
)

func getBaseRequirements(url string) []Requirement {
	return []Requirement{
		{
			Num:         1,
			Description: "Valid CSAF documents",
			Messages:    []Message{{Type: 1, Text: "No remote validator configured"}, {Type: 0, Text: "All advisories validated fine against the schema."}},
		}, {
			Num:         2,
			Description: "Filename",
			Messages:    []Message{{Type: 0, Text: "All found filenames are conforming."}}},
		{
			Num:         3,
			Description: "TLS",
			Messages:    []Message{{Type: 0, Text: "All tested URLs were HTTPS."}}},
		{
			Num:         4,
			Description: "TLP:WHITE",
			Messages:    []Message{{Type: 0, Text: "All advisories labeled TLP:WHITE were freely accessible."}}},
		{
			Num:         5,
			Description: "TLP:AMBER and TLP:RED",
			Messages: []Message{
				{Type: 0, Text: "No advisories labeled TLP:AMBER or TLP:RED tested for accessibility."}}},
		{
			Num:         6,
			Description: "Redirects",
			Messages:    []Message{{Type: 0, Text: "No redirections found."}}},
		{
			Num:         7,
			Description: "provider-metadata.json",
			Messages:    []Message{{Type: 0, Text: "Found good provider metadata."}}},
		{
			Num:         8,
			Description: "security.txt",
			Messages:    []Message{{Type: 0, Text: "Performed no test of security.txt since the direct url of the provider-metadata.json was used."}}},
		{
			Num:         9,
			Description: "/.well-known/csaf/provider-metadata.json",
			Messages:    []Message{{Type: 0, Text: "Performed no test on whether the provider-metadata.json is available under the .well-known path since the direct url of the provider-metadata.json was used."}}},
		{
			Num:         10,
			Description: "DNS path",
			Messages:    []Message{{Type: 0, Text: "Performed no test on the contents of https://csaf.data.security.DOMAIN since the direct url of the provider-metadata.json was used."}}},
		{
			Num:         11,
			Description: "One folder per year",
			Messages:    []Message{{Type: 2, Text: fmt.Sprintf("No year folder found in %s/white/avendor-advisory-0004.json", url)}}},
		{
			Num:         12,
			Description: "index.txt",
			Messages:    []Message{{Type: 0, Text: fmt.Sprintf("Found %s/white/index.txt", url)}}},
		{
			Num:         13,
			Description: "changes.csv",
			Messages:    []Message{{Type: 0, Text: fmt.Sprintf("Found %s/white/changes.csv", url)}}},
		{
			Num:         14,
			Description: "Directory listings",
			Messages:    []Message{{Type: 0, Text: "All directory listings are valid."}}},
		{
			Num:         15,
			Description: "ROLIE feed",
			Messages:    []Message{{Type: 2, Text: "ROLIE feed based distribution was not used."}}},
		{
			Num:         16,
			Description: "ROLIE service document",
			Messages:    []Message{{Type: 1, Text: "No ROLIE service document found."}}},
		{
			Num:         17,
			Description: "ROLIE category document",
			Messages:    []Message{{Type: 1, Text: "No ROLIE category document found."}}},
		{
			Num:         18,
			Description: "Integrity",
			Messages:    []Message{{Type: 0, Text: "All checksums match."}}},
		{
			Num:         19,
			Description: "Signatures",
			Messages:    []Message{{Type: 0, Text: "All signatures verified."}}},
		{
			Num:         20,
			Description: "Public OpenPGP Key",
			Messages:    []Message{{Type: 0, Text: "1 public OpenPGP key(s) loaded."}}},
	}
}

func TestShaMarking(t *testing.T) {
	tests := []struct {
		name              string
		directoryProvider bool
		enableSha256      bool
		enableSha512      bool
		expected          func(string) []Requirement
	}{
		{
			name:              "deliver sha256 and sha512",
			directoryProvider: false,
			enableSha256:      true,
			enableSha512:      true,
			expected:          getBaseRequirements,
		},
		{
			name:              "only deliver sha256",
			directoryProvider: false,
			enableSha256:      true,
			enableSha512:      false,
			expected:          getBaseRequirements,
		},
		{
			name:              "only deliver sha512",
			directoryProvider: false,
			enableSha256:      false,
			enableSha512:      true,
			expected:          getBaseRequirements,
		},
		{
			name:              "only deliver sha256 and sha512, directory provider",
			directoryProvider: true,
			enableSha256:      true,
			enableSha512:      true,
			expected:          getBaseRequirements,
		},
		{
			name:              "only deliver sha256, directory provider",
			directoryProvider: true,
			enableSha256:      true,
			enableSha512:      false,
			expected:          getBaseRequirements,
		},
		{
			name:              "only deliver sha512, directory provider",
			directoryProvider: true,
			enableSha256:      false,
			enableSha512:      true,
			expected:          getBaseRequirements,
		},
	}

	t.Parallel()
	for _, testToRun := range tests {
		test := testToRun
		t.Run(test.name, func(tt *testing.T) {
			tt.Parallel()
			serverURL := ""
			params := testutil.ProviderParams{
				URL:          "",
				EnableSha256: test.enableSha256,
				EnableSha512: test.enableSha512,
			}
			server := httptest.NewTLSServer(testutil.ProviderHandler(&params, test.directoryProvider))
			defer server.Close()

			serverURL = server.URL
			params.URL = server.URL

			hClient := server.Client()
			client := util.Client(hClient)

			cfg := config{}
			err := cfg.prepare()
			if err != nil {
				t.Fatalf("SHA marking config failed: %v", err)
			}
			p, err := newProcessor(&cfg)
			if err != nil {
				t.Fatalf("could not init downloader: %v", err)
			}
			p.client = client

			report, err := p.run([]string{serverURL + "/provider-metadata.json"})
			if err != nil {
				t.Errorf("SHA marking %v: Expected no error, got: %v", test.name, err)
			}
			expected := test.expected(serverURL)
			for i, got := range report.Domains[0].Requirements {
				want := expected[i]
				if !reflect.DeepEqual(*got, want) {
					t.Errorf("SHA marking %v: Expected %v, got %v", test.name, want, *got)
				}
			}

			p.close()
		})
	}
}
