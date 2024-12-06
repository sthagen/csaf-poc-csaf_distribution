// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2023 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2023 Intevation GmbH <https://intevation.de>

package main

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"os"
	"reflect"
	"testing"
	"text/template"

	"github.com/gocsaf/csaf/v3/internal/testutil"
	"github.com/gocsaf/csaf/v3/util"
)

func getRequirementTestData(t *testing.T, params testutil.ProviderParams, directoryProvider bool) []Requirement {
	path := "../../testdata/processor-requirements/"
	if params.EnableSha256 {
		path += "sha256-"
	}
	if params.EnableSha512 {
		path += "sha512-"
	}
	if directoryProvider {
		path += "directory"
	} else {
		path += "rolie"
	}
	path += ".json"

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	tmplt, err := template.New("base").Parse(string(content))
	if err != nil {
		t.Fatal(err)
	}

	var output bytes.Buffer
	err = tmplt.Execute(&output, params)
	if err != nil {
		t.Fatal(err)
	}
	var requirement []Requirement
	err = json.Unmarshal(output.Bytes(), &requirement)
	if err != nil {
		t.Fatal(err)
	}
	return requirement
}

func TestShaMarking(t *testing.T) {
	tests := []struct {
		name              string
		directoryProvider bool
		enableSha256      bool
		enableSha512      bool
	}{
		{
			name:              "deliver sha256 and sha512",
			directoryProvider: false,
			enableSha256:      true,
			enableSha512:      true,
		},
		{
			name:              "only deliver sha256",
			directoryProvider: false,
			enableSha256:      true,
			enableSha512:      false,
		},
		{
			name:              "only deliver sha512",
			directoryProvider: false,
			enableSha256:      false,
			enableSha512:      true,
		},
		{
			name:              "deliver sha256 and sha512, directory provider",
			directoryProvider: true,
			enableSha256:      true,
			enableSha512:      true,
		},
		{
			name:              "only deliver sha256, directory provider",
			directoryProvider: true,
			enableSha256:      true,
			enableSha512:      false,
		},
		{
			name:              "only deliver sha512, directory provider",
			directoryProvider: true,
			enableSha256:      false,
			enableSha512:      true,
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
			expected := getRequirementTestData(t,
				testutil.ProviderParams{
					URL:          serverURL,
					EnableSha256: test.enableSha256,
					EnableSha512: test.enableSha512,
				},
				test.directoryProvider)
			for i, want := range report.Domains[0].Requirements {
				if !reflect.DeepEqual(expected[i], *want) {
					t.Errorf("SHA marking %v: Expected %v, got %v", test.name, *want, expected[i])
				}
			}

			p.close()
		})
	}
}
