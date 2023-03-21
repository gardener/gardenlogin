/*
SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors

SPDX-License-Identifier: Apache-2.0
*/
package main

import (
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/kubernetes/scheme"
	clientauthenticationv1 "k8s.io/client-go/pkg/apis/clientauthentication/v1"
	clientauthenticationv1beta1 "k8s.io/client-go/pkg/apis/clientauthentication/v1beta1"

	"github.com/gardener/gardenlogin/cmd"
	"github.com/gardener/gardenlogin/internal/clientauthentication"
)

func main() {
	utilruntime.Must(clientauthenticationv1beta1.AddToScheme(scheme.Scheme))
	utilruntime.Must(clientauthenticationv1.AddToScheme(scheme.Scheme))

	// we register our manual conversion between clientauthenticationv1beta1.ExecCredential and clientauthenticationv1.ExecCredential
	utilruntime.Must(clientauthentication.AddConversionFuncs(scheme.Scheme))

	cmd.Execute()
}
