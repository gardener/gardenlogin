/*
SPDX-FileCopyrightText: Contributors to the Gardener project

SPDX-License-Identifier: Apache-2.0
*/

package store

import (
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/gardener/gardenlogin/internal/certificatecache"
)

var _ = Describe("Store", func() {
	s := Store{}

	BeforeEach(func() {
		var err error

		s = Store{}
		s.Dir, err = os.MkdirTemp("", "store")
		Expect(err).ToNot(HaveOccurred())
	})

	AfterEach(func() {
		Expect(os.RemoveAll(s.Dir)).To(Succeed())
	})

	Describe("FindByKey", func() {
		It("should succeed", func() {
			key := certificatecache.Key{
				ShootServer:                   "https://api.example.com",
				ShootCertificateAuthorityHash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
				ShootName:                     "mycluster",
				ShootNamespace:                "garden-myproject",
				GardenClusterIdentity:         "landscape-dev",
				AccessLevel:                   "viewer",
			}
			json := "{\"clientCertificateData\":\"Zm9v\",\"clientKeyData\":\"YmFy\"}"
			filename, err := generateFilename(key)
			Expect(err).ToNot(HaveOccurred())

			p := filepath.Join(s.Dir, filename)
			Expect(os.WriteFile(p, []byte(json), 0o600)).To(Succeed())

			got, err := s.FindByKey(key)
			Expect(err).ToNot(HaveOccurred())

			want := &certificatecache.CertificateSet{ClientCertificateData: []byte("foo"), ClientKeyData: []byte("bar")}
			Expect(want).To(Equal(got))
		})
	})

	Describe("Save", func() {
		It("should succeed", func() {
			key := certificatecache.Key{
				ShootServer:                   "https://api.example.com",
				ShootCertificateAuthorityHash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
				ShootName:                     "mycluster",
				ShootNamespace:                "garden-myproject",
				GardenClusterIdentity:         "landscape-dev",
				AccessLevel:                   "viewer",
			}
			certificateSet := certificatecache.CertificateSet{ClientCertificateData: []byte("foo"), ClientKeyData: []byte("bar")}
			Expect(s.Save(key, certificateSet)).To(Succeed())

			filename, err := generateFilename(key)
			Expect(err).ToNot(HaveOccurred())

			p := filepath.Join(s.Dir, filename)
			gotBytes, err := os.ReadFile(p)
			Expect(err).ToNot(HaveOccurred())

			want := "{\"clientCertificateData\":\"Zm9v\",\"clientKeyData\":\"YmFy\"}\n"
			got := string(gotBytes)
			Expect(want).To(Equal(got))
		})

		It("should generate different filenames for different certificate authority hashes", func() {
			key1 := certificatecache.Key{
				ShootServer:                   "https://api.example.com",
				ShootCertificateAuthorityHash: "hash-ca-1",
				ShootName:                     "mycluster",
				ShootNamespace:                "garden-myproject",
				GardenClusterIdentity:         "landscape-dev",
				AccessLevel:                   "viewer",
			}
			key2 := certificatecache.Key{
				ShootServer:                   "https://api.example.com",
				ShootCertificateAuthorityHash: "hash-ca-2",
				ShootName:                     "mycluster",
				ShootNamespace:                "garden-myproject",
				GardenClusterIdentity:         "landscape-dev",
				AccessLevel:                   "viewer",
			}

			filename1, err := generateFilename(key1)
			Expect(err).ToNot(HaveOccurred())

			filename2, err := generateFilename(key2)
			Expect(err).ToNot(HaveOccurred())

			Expect(filename1).ToNot(Equal(filename2))
		})
	})
})
