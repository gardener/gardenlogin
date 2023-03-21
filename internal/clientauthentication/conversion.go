/*
SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors

SPDX-License-Identifier: Apache-2.0
*/

package clientauthentication

import (
	"errors"

	"k8s.io/apimachinery/pkg/conversion"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/pkg/apis/clientauthentication"
	clientauthenticationv1 "k8s.io/client-go/pkg/apis/clientauthentication/v1"
	clientauthenticationv1beta1 "k8s.io/client-go/pkg/apis/clientauthentication/v1beta1"
)

// AddConversionFuncs registers conversion functions that convert between clientauthenticationv1beta1.ExecCredential and clientauthenticationv1.ExecCredential
// by passing objects of those types to the provided function.
func AddConversionFuncs(scheme *runtime.Scheme) error {
	if err := scheme.AddConversionFunc(&clientauthenticationv1beta1.ExecCredential{}, &clientauthenticationv1.ExecCredential{}, func(a, b interface{}, scope conversion.Scope) error {
		v1beta1ExecCredential, ok := a.(*clientauthenticationv1beta1.ExecCredential)
		if !ok {
			return errors.New("a is not a v1beta1 ExecCredential")
		}

		internalVersion := &clientauthentication.ExecCredential{}
		err := clientauthenticationv1beta1.Convert_v1beta1_ExecCredential_To_clientauthentication_ExecCredential(v1beta1ExecCredential, internalVersion, scope)
		if err != nil {
			return err
		}

		return clientauthenticationv1.Convert_clientauthentication_ExecCredential_To_v1_ExecCredential(internalVersion, b.(*clientauthenticationv1.ExecCredential), scope)
	}); err != nil {
		return err
	}

	return scheme.AddConversionFunc(&clientauthenticationv1.ExecCredential{}, &clientauthenticationv1beta1.ExecCredential{}, func(a, b interface{}, scope conversion.Scope) error {
		v1ExecCredential, ok := a.(*clientauthenticationv1.ExecCredential)
		if !ok {
			return errors.New("a is not a v1 ExecCredential")
		}

		internalVersion := &clientauthentication.ExecCredential{}
		err := clientauthenticationv1.Convert_v1_ExecCredential_To_clientauthentication_ExecCredential(v1ExecCredential, internalVersion, scope)
		if err != nil {
			return err
		}

		return clientauthenticationv1beta1.Convert_clientauthentication_ExecCredential_To_v1beta1_ExecCredential(internalVersion, b.(*clientauthenticationv1beta1.ExecCredential), scope)
	})
}
