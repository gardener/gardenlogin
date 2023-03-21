/*
SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors

SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"fmt"
)

// Config holds the gardenlogin config.
type Config struct {
	// Gardens is a list of known Garden clusters
	Gardens []Garden `yaml:"gardens"`
}

// Garden holds the config of a garden cluster.
type Garden struct {
	// Identity is the cluster identity of the garden cluster.
	// See cluster-identity ConfigMap in kube-system namespace of the garden cluster
	Identity string `yaml:"identity"`

	// Kubeconfig holds the path for the kubeconfig of the garden cluster
	Kubeconfig string `yaml:"kubeconfig"`

	// Context overrides the current-context of the garden cluster kubeconfig
	// +optional
	Context string `yaml:"context"`
}

// FindGarden returns the garden cluster config for a given cluster identity.
// It returns an error if no matching garden cluster with the given cluster identity was found.
func (c *Config) FindGarden(clusterIdentity string) (*Garden, error) {
	for _, cluster := range c.Gardens {
		if cluster.Identity == clusterIdentity {
			return &cluster, nil
		}
	}

	return nil, fmt.Errorf("no garden cluster configured for cluster identity: %s", clusterIdentity)
}
