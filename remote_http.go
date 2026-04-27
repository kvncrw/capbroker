// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

func remoteURL(server, path string) string {
	return strings.TrimRight(server, "/") + path
}

func postJSON(url string, request, response interface{}) error {
	body, err := json.Marshal(request)
	if err != nil {
		return err
	}
	resp, err := http.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return decodeRemoteResponse(resp, response)
}

// postJSONWithHeader is postJSON plus one extra request header. Used by
// the operator-side review CLI to forward operator identity via the same
// trusted-header path the HTTP form uses (Cf-Access-Authenticated-User-Email),
// so audit attribution is identical regardless of front door.
func postJSONWithHeader(url string, request, response interface{}, headerName, headerValue string) error {
	body, err := json.Marshal(request)
	if err != nil {
		return err
	}
	httpReq, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if headerName != "" {
		httpReq.Header.Set(headerName, headerValue)
	}
	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return decodeRemoteResponse(resp, response)
}

func getJSON(url string, response interface{}) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return decodeRemoteResponse(resp, response)
}

func decodeRemoteResponse(resp *http.Response, response interface{}) error {
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		var errBody struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(data, &errBody) == nil && errBody.Error != "" {
			return fmt.Errorf("%s: %s", resp.Status, errBody.Error)
		}
		return fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(data)))
	}
	if response == nil {
		return nil
	}
	if err := json.Unmarshal(data, response); err != nil {
		return fmt.Errorf("parse %s: %w", resp.Request.URL, err)
	}
	return nil
}
