/*
SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors

SPDX-License-Identifier: Apache-2.0
*/

package cmd_test

import (
	"testing"

	"github.com/gardener/gardener/pkg/apis/authentication"
	authenticationv1alpha1 "github.com/gardener/gardener/pkg/apis/authentication/v1alpha1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	clientauthenticationv1 "k8s.io/client-go/pkg/apis/clientauthentication/v1"
	clientauthenticationv1beta1 "k8s.io/client-go/pkg/apis/clientauthentication/v1beta1"

	"github.com/gardener/gardenlogin/internal/clientauthentication"
)

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
	RunSpecs(t, "Cmd Suite")
}
