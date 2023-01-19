/*
SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors

SPDX-License-Identifier: Apache-2.0
*/

package store

import (
	"crypto/sha256"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/gardener/gardenlogin/internal/certificatecache"
)

// Interface defines functions to read and write to the certificate store
type Interface interface {
	// FindByKey returns the certificatecache.CertificateSet for a given key
	FindByKey(key certificatecache.Key) (*certificatecache.CertificateSet, error)
	// Save stores the given certificatecache.CertificateSet for the given key
	Save(key certificatecache.Key, certificateSet certificatecache.CertificateSet) error
}

type entity struct {
	ClientCertificateData []byte `json:"clientCertificateData,omitempty"`
	ClientKeyData         []byte `json:"clientKeyData,omitempty"`
}

// Store provides access to the certificate cache on the local filesystem.
// Filename of a certificate cache is sha256 digest of the shoot server, shoot name, shoot namespace and garden cluster identity
type Store struct {
	// Dir is the backing directory of the store credentials
	Dir string
}

// FindByKey returns the certificatecache.CertificateSet for a given key
func (s *Store) FindByKey(key certificatecache.Key) (*certificatecache.CertificateSet, error) {
	filename, err := generateFilename(key)
	if err != nil {
		return nil, err
	}

	path := filepath.Join(s.Dir, filename)

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	defer f.Close()

	d := json.NewDecoder(f)

	var e entity
	if err := d.Decode(&e); err != nil {
		return nil, err
	}

	return &certificatecache.CertificateSet{
		ClientCertificateData: e.ClientCertificateData,
		ClientKeyData:         e.ClientKeyData,
	}, nil
}

// Save stores the given certificatecache.CertificateSet for the given key
func (s *Store) Save(key certificatecache.Key, certificateSet certificatecache.CertificateSet) error {
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}

	filename, err := generateFilename(key)
	if err != nil {
		return err
	}

	path := filepath.Join(s.Dir, filename)

	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}

	defer f.Close()

	e := entity{
		ClientCertificateData: certificateSet.ClientCertificateData,
		ClientKeyData:         certificateSet.ClientKeyData,
	}

	return json.NewEncoder(f).Encode(&e)
}

func generateFilename(key certificatecache.Key) (string, error) {
	s := sha256.New()
	e := gob.NewEncoder(s)

	if err := e.Encode(&key); err != nil {
		return "", err
	}

	return hex.EncodeToString(s.Sum(nil)), nil
}
