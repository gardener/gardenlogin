/*
SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors

SPDX-License-Identifier: Apache-2.0
*/

package store

import (
	"io/ioutil"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/gardener/gardenlogin/internal/certificatecache"
)

var _ = Describe("Store", func() {
	var (
		s = Store{}
	)

	BeforeEach(func() {
		var err error
		s = Store{}
		s.Dir, err = ioutil.TempDir("", "store")
		Expect(err).ToNot(HaveOccurred())
	})

	AfterEach(func() {
		Expect(os.RemoveAll(s.Dir)).To(Succeed())
	})

	Describe("FindByKey", func() {

		It("should succeed", func() {
			key := certificatecache.Key{
				ShootServer:           "https://api.example.com",
				ShootName:             "mycluster",
				ShootNamespace:        "garden-myproject",
				GardenClusterIdentity: "landscape-dev",
			}
			json := "{\"clientCertificateData\":\"Zm9v\",\"clientKeyData\":\"YmFy\"}"
			filename, err := generateFilename(key)
			Expect(err).ToNot(HaveOccurred())

			p := filepath.Join(s.Dir, filename)
			Expect(ioutil.WriteFile(p, []byte(json), 0600)).To(Succeed())

			got, err := s.FindByKey(key)
			Expect(err).ToNot(HaveOccurred())

			want := &certificatecache.CertificateSet{ClientCertificateData: []byte("foo"), ClientKeyData: []byte("bar")}
			Expect(want).To(Equal(got))
		})
	})

	Describe("Save", func() {

		It("should succeed", func() {
			key := certificatecache.Key{
				ShootServer:           "https://api.example.com",
				ShootName:             "mycluster",
				ShootNamespace:        "garden-myproject",
				GardenClusterIdentity: "landscape-dev",
			}
			certificateSet := certificatecache.CertificateSet{ClientCertificateData: []byte("foo"), ClientKeyData: []byte("bar")}
			Expect(s.Save(key, certificateSet)).To(Succeed())

			filename, err := generateFilename(key)
			Expect(err).ToNot(HaveOccurred())

			p := filepath.Join(s.Dir, filename)
			gotBytes, err := ioutil.ReadFile(p)
			Expect(err).ToNot(HaveOccurred())

			want := "{\"clientCertificateData\":\"Zm9v\",\"clientKeyData\":\"YmFy\"}\n"
			got := string(gotBytes)
			Expect(want).To(Equal(got))
		})
	})
})
