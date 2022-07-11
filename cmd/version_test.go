/*
SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors

SPDX-License-Identifier: Apache-2.0
*/

package cmd_test

import (
	"github.com/gardener/gardenlogin/cmd"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/cli-runtime/pkg/genericclioptions"
)

var _ = Describe("Version", func() {

	It("should print version", func() {
		streams, _, out, _ := genericclioptions.NewTestIOStreams()
		o := cmd.NewVersionOptions(streams)
		err := o.Validate()
		Expect(err).ToNot(HaveOccurred())

		err = o.Run()
		Expect(err).ToNot(HaveOccurred())

		Expect(out.String()).To(ContainSubstring("GitVersion"))
	})
})
