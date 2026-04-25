// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

type remoteStore struct {
	path string
	mu   sync.Mutex
}

func newRemoteStore(stateDir string) remoteStore {
	return remoteStore{path: filepath.Join(stateDir, "remote-requests.json")}
}

func (s *remoteStore) list() ([]RemoteRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loadLocked()
}

func (s *remoteStore) get(id string) (RemoteRequest, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	requests, err := s.loadLocked()
	if err != nil {
		return RemoteRequest{}, false, err
	}
	for _, req := range requests {
		if req.ID == id {
			return req, true, nil
		}
	}
	return RemoteRequest{}, false, nil
}

func (s *remoteStore) create(req RemoteRequest) (RemoteRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	requests, err := s.loadLocked()
	if err != nil {
		return RemoteRequest{}, err
	}
	requests = append(requests, req)
	return req, s.saveLocked(requests)
}

func (s *remoteStore) update(id string, update func(*RemoteRequest) error) (RemoteRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	requests, err := s.loadLocked()
	if err != nil {
		return RemoteRequest{}, err
	}
	for i := range requests {
		if requests[i].ID != id {
			continue
		}
		if err := update(&requests[i]); err != nil {
			return RemoteRequest{}, err
		}
		return requests[i], s.saveLocked(requests)
	}
	return RemoteRequest{}, fmt.Errorf("request %s not found", id)
}

func (s *remoteStore) loadLocked() ([]RemoteRequest, error) {
	data, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var requests []RemoteRequest
	if err := json.Unmarshal(data, &requests); err != nil {
		return nil, fmt.Errorf("parse remote requests: %w", err)
	}
	return requests, nil
}

func (s *remoteStore) saveLocked(requests []RemoteRequest) error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(requests, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}
