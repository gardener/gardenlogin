/*
SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors

SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"fmt"

	"k8s.io/klog/v2"
)

// Config holds the gardenlogin config
type Config struct {
	// Gardens is a list of known Garden clusters
	Gardens []Garden `yaml:"gardens"`

	// GardenClusters is a list of known Garden clusters
	// Deprecated: use Gardens instead
	GardenClusters []GardenClusterConfig `yaml:"gardenClusters"`
}

// Garden holds the config of a garden cluster
type Garden struct {
	// Identity is the cluster identity of the garden cluster.
	// See cluster-identity ConfigMap in kube-system namespace of the garden cluster
	Identity string `yaml:"identity"`

	// Kubeconfig holds the path for the kubeconfig of the garden cluster
	Kubeconfig string `yaml:"kubeconfig"`
}

// GardenClusterConfig holds the config of a garden cluster
// Deprecated: use Garden instead
type GardenClusterConfig struct {
	// ClusterIdentity is the cluster identifier of the garden cluster.
	// Deprecated: use Garden.Identity instead
	ClusterIdentity string `yaml:"clusterIdentity"`

	// Kubeconfig holds the path for the kubeconfig of the garden cluster
	// Deprecated: use Garden.Kubeconfig instead
	Kubeconfig string `yaml:"kubeconfig"`
}

// FindGarden returns the garden cluster config for a given cluster identity.
// It returns an error if no matching garden cluster with the given cluster identity was found.
func (c *Config) FindGarden(clusterIdentity string) (*Garden, error) {
	for _, cluster := range c.Gardens {
		if cluster.Identity == clusterIdentity {
			return &cluster, nil
		}
	}

	// fallback logic with deprecated properties
	gardenClusters := c.GardenClusters
	for _, cluster := range gardenClusters {
		if cluster.ClusterIdentity == clusterIdentity {
			klog.Warningln("Your are using deprecated config properties for gardenlogin. Please update your config file as these properties will not be supported in future versions. \"gardenClusters\" was renamed to \"gardens\", \"clusterIdentity\" was renamed to \"identity\".\n")
			return &Garden{
				Identity:   cluster.ClusterIdentity,
				Kubeconfig: cluster.Kubeconfig,
			}, nil
		}
	}

	return nil, fmt.Errorf("no garden cluster configured for cluster identity: %s", clusterIdentity)
}
