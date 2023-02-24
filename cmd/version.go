/*
SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors

SPDX-License-Identifier: Apache-2.0
*/

package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
	"k8s.io/component-base/version"

	"github.com/gardener/gardenlogin/internal/cmd/util"
)

// VersionOptions is a struct to support version command.
type VersionOptions struct {
	// Short indicates if just the version number should be printed
	Short bool
	// Output defines the output format of the version information. Either 'yaml' or 'json'
	Output string

	// IOStreams provides the standard names for iostreams
	IOStreams util.IOStreams
}

// NewVersionOptions returns initialized VersionOptions.
func NewVersionOptions(ioStreams util.IOStreams) *VersionOptions {
	return &VersionOptions{
		IOStreams: ioStreams,
	}
}

// NewVersionCmd returns a new version command.
func NewVersionCmd() *cobra.Command {
	o := NewVersionOptions(ioStreams)
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print the gardenlogin version information",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := o.Validate(); err != nil {
				return err
			}

			return o.Run()
		},
	}

	cmd.Flags().BoolVar(&o.Short, "short", o.Short, "If true, print just the version number.")
	cmd.Flags().StringVarP(&o.Output, "output", "o", o.Output, "One of 'yaml' or 'json'.")

	return cmd
}

var versionCmd = NewVersionCmd()

func init() {
	rootCmd.AddCommand(versionCmd)
}

// Validate validates the provided options.
func (o *VersionOptions) Validate() error {
	if o.Output != "" && o.Output != "yaml" && o.Output != "json" {
		return fmt.Errorf(`--output must be 'yaml' or 'json'`)
	}

	return nil
}

// Run executes version command.
func (o *VersionOptions) Run() error {
	versionInfo := version.Get()

	switch o.Output {
	case "":
		if o.Short {
			fmt.Fprintf(o.IOStreams.Out, "Version: %s\n", versionInfo.GitVersion)
		} else {
			fmt.Fprintf(o.IOStreams.Out, "Version: %s\n", fmt.Sprintf("%#v", versionInfo))
		}
	case "yaml":
		marshalled, err := yaml.Marshal(&versionInfo)
		if err != nil {
			return err
		}

		fmt.Fprintln(o.IOStreams.Out, string(marshalled))
	case "json":
		marshalled, err := json.MarshalIndent(&versionInfo, "", "  ")
		if err != nil {
			return err
		}

		fmt.Fprintln(o.IOStreams.Out, string(marshalled))
	default:
		// There is a bug in the program if we hit this case.
		// However, we follow a policy of never panicking.
		return fmt.Errorf("options were not validated: --output=%q should have been rejected", o.Output)
	}

	return nil
}
