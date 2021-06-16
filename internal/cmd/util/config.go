/*
SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors

SPDX-License-Identifier: Apache-2.0
*/

package util

import "fmt"

// GardenloginConfig holds the gardenlogin config
type GardenloginConfig struct {
	GardenClusters []GardenClusterConfig
}

// GardenClusterConfig holds the config of a garden cluster
type GardenClusterConfig struct {
	// ClusterIdentity is the cluster identifier of the garden cluster.
	// See cluster-identity ConfigMap in kube-system namespace of the garden cluster
	ClusterIdentity string
	// Kubeconfig holds the path for the kubeconfig of the garden cluster
	Kubeconfig string
}

// GetClusterConfigForClusterIdentity returns the garden cluster for a given cluster identity.
// It returns an error if no matching garden cluster with the given cluster identity was found.
func (c *GardenloginConfig) GetClusterConfigForClusterIdentity(clusterIdentity string) (*GardenClusterConfig, error) {
	gardenClusters := c.GardenClusters
	for _, cluster := range gardenClusters {
		if cluster.ClusterIdentity == clusterIdentity {
			return &cluster, nil
		}
	}

	return nil, fmt.Errorf("no garden cluster configured for cluster identity: %s", clusterIdentity)
}
