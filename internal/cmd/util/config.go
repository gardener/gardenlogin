/*
SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors

SPDX-License-Identifier: Apache-2.0
*/

package util

import "fmt"

type GardenLoginConfig struct {
	GardenClusters []GardenClusterConfig
}

type GardenClusterConfig struct {
	ClusterIdentity string
	Kubeconfig      string
}

func (c *GardenLoginConfig) GetClusterConfigForClusterIdentity(clusterIdentity string) (*GardenClusterConfig, error) {
	gardenClusters := c.GardenClusters
	for _, cluster := range gardenClusters {
		if cluster.ClusterIdentity == clusterIdentity {
			return &cluster, nil
		}
	}

	return nil, fmt.Errorf("no garden cluster configured for cluster identity: %s", clusterIdentity)
}
