// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2023 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2023 Intevation GmbH <https://intevation.de>

package main

import (
	"net/http/httptest"
	"testing"

	"github.com/gocsaf/csaf/v3/internal/testutil"
	"github.com/gocsaf/csaf/v3/util"
)

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
			name:              "only deliver sha256 and sha512, directory provider",
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

			// TODO check result of processor
			_, err = p.run([]string{serverURL + "/provider-metadata.json"})
			if err != nil {
				t.Errorf("SHA marking %v: Expected no error, got: %v", test.name, err)
			}
			p.close()
		})
	}
}
