/*
SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors

SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"fmt"

	gardencoreclientset "github.com/gardener/gardener/pkg/client/core/clientset/versioned"
	"github.com/mitchellh/go-homedir"
	"github.com/spf13/viper"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/gardener/gardenlogin/internal/certificatecache/store"
)

// Factory provides abstractions that allow the command to be extended across multiple types of resources and different API sets.
type Factory interface {
	// Clock returns a clock that provides access to the current time.
	Clock() Clock

	// RESTClient returns the rest client for the garden cluster, identified by the garden cluster identity
	RESTClient(gardenClusterIdentity string) (rest.Interface, error)

	// HomeDir returns the home directory for the executing user.
	HomeDir() string

	// CertificateStore returns a certificate store
	CertificateStore(dir string) store.Interface
}

// factoryImpl implements util.Factory interface
type factoryImpl struct {
	homeDirectory string

	config *Config
}

var _ Factory = &factoryImpl{}

// NewFactory returns a new util.Factory.
func NewFactory(homeDirectory string) Factory {
	return &factoryImpl{
		homeDirectory: homeDirectory,
	}
}

// Clock returns a clock that provides access to the current time.
func (f *factoryImpl) Clock() Clock {
	return &RealClock{}
}

// RESTClient returns the rest client for the garden cluster, identified by the garden cluster identity
func (f *factoryImpl) RESTClient(gardenClusterIdentity string) (rest.Interface, error) {
	config, err := f.getConfig()
	if err != nil {
		return nil, err
	}

	garden, err := config.FindGarden(gardenClusterIdentity)
	if err != nil {
		return nil, err
	}

	kubeconfigPath, err := homedir.Expand(garden.Kubeconfig)
	if err != nil {
		return nil, err
	}

	gardenConfig, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		&clientcmd.ClientConfigLoadingRules{ExplicitPath: kubeconfigPath},
		&clientcmd.ConfigOverrides{CurrentContext: garden.Context},
	).ClientConfig()
	if err != nil {
		return nil, err
	}

	gardenCore, err := gardencoreclientset.NewForConfig(gardenConfig)
	if err != nil {
		return nil, err
	}

	return gardenCore.CoreV1beta1().RESTClient(), nil
}

// HomeDir returns the home directory for the executing user.
func (f *factoryImpl) HomeDir() string {
	return f.homeDirectory
}

// CertificateStore returns a certificate store
func (f *factoryImpl) CertificateStore(dir string) store.Interface {
	return &store.Store{Dir: dir}
}

func (f *factoryImpl) getConfig() (*Config, error) {
	if f.config != nil {
		return f.config, nil
	}

	config := &Config{}
	if err := viper.Unmarshal(config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal viper config: %w", err)
	}

	f.config = config

	return config, nil
}
