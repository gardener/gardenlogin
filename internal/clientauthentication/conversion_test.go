/*
SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors

SPDX-License-Identifier: Apache-2.0
*/

package clientauthentication_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/runtime"
	clientauthenticationv1 "k8s.io/client-go/pkg/apis/clientauthentication/v1"
	clientauthenticationv1beta1 "k8s.io/client-go/pkg/apis/clientauthentication/v1beta1"

	"github.com/gardener/gardenlogin/internal/clientauthentication"
)

var _ = Describe("AddConversionFuncs", func() {
	var scheme *runtime.Scheme

	BeforeEach(func() {
		scheme = runtime.NewScheme()

		Expect(clientauthenticationv1beta1.AddToScheme(scheme)).To(Succeed())
		Expect(clientauthenticationv1.AddToScheme(scheme)).To(Succeed())

		Expect(clientauthentication.AddConversionFuncs(scheme)).To(Succeed())
	})

	It("should convert from v1beta1 to v1 ExecCredential type", func() {
		// Create v1beta1 ExecCredential instance
		v1beta1ExecCredential := &clientauthenticationv1beta1.ExecCredential{
			Spec: clientauthenticationv1beta1.ExecCredentialSpec{
				Cluster: &clientauthenticationv1beta1.Cluster{
					Server: "https://kubernetes",
				},
			},
		}

		// Convert v1beta1 to v1 ExecCredential
		obj, err := scheme.ConvertToVersion(v1beta1ExecCredential, clientauthenticationv1.SchemeGroupVersion)
		Expect(err).NotTo(HaveOccurred())

		v1ExecCredential, ok := obj.(*clientauthenticationv1.ExecCredential)
		Expect(ok).To(BeTrue())

		// Ensure that v1beta1 ExecCredential field match the original v1 instance.
		// We do not test all fields, as we do not want to test the auto generated conversions
		Expect(v1ExecCredential.Spec.Cluster.Server).To(Equal("https://kubernetes"))
	})

	It("should convert from v1 to v1beta1 ExecCredential type", func() {
		// Create v1beta1 ExecCredential instance
		v1ExecCredential := &clientauthenticationv1.ExecCredential{
			Spec: clientauthenticationv1.ExecCredentialSpec{
				Cluster: &clientauthenticationv1.Cluster{
					Server: "https://kubernetes",
				},
			},
		}

		// Convert v1beta1 to v1 ExecCredential
		obj, err := scheme.ConvertToVersion(v1ExecCredential, clientauthenticationv1beta1.SchemeGroupVersion)
		Expect(err).NotTo(HaveOccurred())

		v1beta1ExecCredential, ok := obj.(*clientauthenticationv1beta1.ExecCredential)
		Expect(ok).To(BeTrue())

		// Ensure that v1beta1 ExecCredential field match the original v1 instance.
		// We do not test all fields, as we do not want to test the auto generated conversions
		Expect(v1beta1ExecCredential.Spec.Cluster.Server).To(Equal("https://kubernetes"))
	})
})
