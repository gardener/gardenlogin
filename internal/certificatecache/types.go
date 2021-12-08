/*
SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors

SPDX-License-Identifier: Apache-2.0
*/

package certificatecache

// Key represents a key of a certificate cache.
type Key struct {
	// ShootServer is the kube-apiserver url of the shoot
	ShootServer string
	// ShootName is the name of the shoot in the garden cluster
	ShootName string
	// ShootNamespace is the namespace of the shoot in the garden cluster
	ShootNamespace string
	// GardenClusterIdentity is the cluster identity of the garden cluster.
	// See cluster-identity ConfigMap in kube-system namespace of the garden cluster
	GardenClusterIdentity string
}

// CertificateSet represents a set of client certificate and client key.
type CertificateSet struct {
	ClientCertificateData []byte
	ClientKeyData         []byte
}
