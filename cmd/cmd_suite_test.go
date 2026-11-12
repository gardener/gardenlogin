/*
SPDX-FileCopyrightText: Contributors to the Gardener project

SPDX-License-Identifier: Apache-2.0
*/

package cmd_test

import (
	"testing"
	"time"

	"github.com/gardener/gardener/pkg/apis/authentication"
	authenticationv1alpha1 "github.com/gardener/gardener/pkg/apis/authentication/v1alpha1"
	"github.com/gardener/gardener/pkg/utils/secrets"
	"github.com/gardener/gardener/pkg/utils/test"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	clientauthenticationv1 "k8s.io/client-go/pkg/apis/clientauthentication/v1"
	clientauthenticationv1beta1 "k8s.io/client-go/pkg/apis/clientauthentication/v1beta1"
	testingclock "k8s.io/utils/clock/testing"

	c "github.com/gardener/gardenlogin/cmd"
	"github.com/gardener/gardenlogin/internal/clientauthentication"
)

var (
	sharedCaCert     *secrets.Certificate
	sharedClientCert *secrets.Certificate
)

var _ = BeforeSuite(func() {
	restore := test.WithVar(&secrets.Clock, testingclock.NewFakeClock(fakeNow()))
	defer restore()

	sharedCaCert = generateCaCert()
	sharedClientCert = generateClientCert(sharedCaCert, 10*time.Minute)
})

func init() {
	scheme := clientgoscheme.Scheme

	utilruntime.Must(authenticationv1alpha1.AddToScheme(scheme))
	utilruntime.Must(authentication.AddToScheme(scheme))

	utilruntime.Must(clientauthenticationv1beta1.AddToScheme(scheme))
	utilruntime.Must(clientauthenticationv1.AddToScheme(scheme))

	utilruntime.Must(clientauthentication.AddConversionFuncs(scheme))
}

func TestCmd(t *testing.T) {
	RegisterFailHandler(Fail)

	suiteConfig, reporterConfig := GinkgoConfiguration()
	if suiteConfig.LabelFilter == "" {
		if c.IsInsecureArgumentOnlyAllowed() {
			suiteConfig.LabelFilter = "!argument-only-disabled"
		} else {
			suiteConfig.LabelFilter = "!argument-only-enabled"
		}
	}

	RunSpecs(t, "Cmd Suite", suiteConfig, reporterConfig)
}
