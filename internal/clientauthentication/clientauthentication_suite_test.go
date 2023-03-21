/*
SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors

SPDX-License-Identifier: Apache-2.0
*/

package clientauthentication_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientauthenticationv1 "k8s.io/client-go/pkg/apis/clientauthentication/v1"
	clientauthenticationv1beta1 "k8s.io/client-go/pkg/apis/clientauthentication/v1beta1"

	"github.com/gardener/gardenlogin/internal/clientauthentication"
)

var scheme = runtime.NewScheme()

func init() {
	utilruntime.Must(clientauthenticationv1beta1.AddToScheme(scheme))
	utilruntime.Must(clientauthenticationv1.AddToScheme(scheme))

	utilruntime.Must(clientauthentication.AddConversionFuncs(scheme))
}

func TestCmd(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Clientauthentication Suite")
}
