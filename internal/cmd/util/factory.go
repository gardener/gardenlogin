/*
SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors

SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	gardencoreclientset "github.com/gardener/gardener/pkg/client/core/clientset/versioned"
	"github.com/mitchellh/go-homedir"
	"github.com/spf13/viper"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// Factory provides abstractions that allow the command to be extended across multiple types of resources and different API sets.
type Factory interface {
	// RESTClient returns the rest client for the garden cluster, identified by the garden cluster identity
	RESTClient(gardenClusterIdentity string) (rest.Interface, error)

	// HomeDir returns the home directory for the executing user.
	HomeDir() string
}

// FactoryImpl implements util.Factory interface
type FactoryImpl struct {
	HomeDirectory string
}

func (f *FactoryImpl) RESTClient(gardenClusterIdentity string) (rest.Interface, error) {
	config := &GardenLoginConfig{}
	if err := viper.Unmarshal(config); err != nil {
		return nil, err
	}

	gardenClusterConfig, err := config.GetClusterConfigForClusterIdentity(gardenClusterIdentity)
	if err != nil {
		return nil, err
	}

	// TODO allow to select context
	kubeconfig, err := homedir.Expand(gardenClusterConfig.Kubeconfig)
	if err != nil {
		return nil, err
	}

	// use the current context in kubeconfig
	gardenConfig, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return nil, err
	}

	gardenCore, err := gardencoreclientset.NewForConfig(gardenConfig)
	if err != nil {
		return nil, err
	}

	return gardenCore.CoreV1beta1().RESTClient(), nil
}

func (f *FactoryImpl) HomeDir() string {
	return f.HomeDirectory
}
