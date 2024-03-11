/*
SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors

SPDX-License-Identifier: Apache-2.0
*/

package cmd

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/iancoleman/strcase"
	"github.com/mitchellh/go-homedir"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	cliflag "k8s.io/component-base/cli/flag"
	"k8s.io/klog/v2"
)

const (
	envPrefix        = "GL"
	envGardenHomeDir = envPrefix + "_HOME"
	envConfigName    = envPrefix + "_CONFIG_NAME"

	gardenHomeFolder = ".garden"
	configName       = "gardenlogin"
)

var cfgFile string

// rootCmd represents the base command when called without any subcommands.
var rootCmd = &cobra.Command{
	Use:   "gardenlogin",
	Short: "gardenlogin is a kubectl credential plugin for shoot cluster admin authentication",
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	cobra.CheckErr(rootCmd.Execute())
}

func init() {
	cobra.OnInitialize(initConfig)

	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.
	flags := rootCmd.PersistentFlags()
	// Normalize all flags that are coming from other packages or pre-configurations
	// a.k.a. change all "_" to "-". e.g. klog package
	flags.SetNormalizeFunc(cliflag.WordSepNormalizeFunc)

	addKlogFlags(flags)

	flags.StringVar(&cfgFile, "config", "", fmt.Sprintf("config file (default is %s)", filepath.Join("~", gardenHomeFolder, configName+".yaml")))
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	ctx := context.Background()
	logger := klog.FromContext(ctx)

	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := homedir.Dir()
		cobra.CheckErr(err)

		configPath := filepath.Join(home, gardenHomeFolder)

		// Search config in ~/.garden or in path provided with the env variable GL_HOME with name "gardenlogin" (without extension) or name from env variable GL_CONFIG_NAME.
		envHomeDir, err := homedir.Expand(os.Getenv(envGardenHomeDir))
		cobra.CheckErr(err)

		viper.AddConfigPath(envHomeDir)
		viper.AddConfigPath(configPath)

		if os.Getenv(envConfigName) != "" {
			viper.SetConfigName(os.Getenv(envConfigName))
		} else {
			viper.SetConfigName(configName)
		}
	}

	viper.SetEnvPrefix(envPrefix)
	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := readInConfig(); err != nil {
		logger.Error(err, "failed to read config file")
	}

	logger.V(4).Info("Loaded Gardenlogin config", "file", viper.ConfigFileUsed())

	getClientCertificateCmd.Flags().VisitAll(func(flag *pflag.Flag) {
		viperKey := strcase.ToLowerCamel(flag.Name)

		if strings.Contains(flag.Name, "-") {
			envVarSuffix := strcase.ToScreamingSnake(flag.Name)
			envVar := fmt.Sprintf("%s_%s", envPrefix, envVarSuffix)

			if err := viper.BindEnv(viperKey, envVar); err != nil {
				logger.Info("Failed to bind config key to env variable", "key", viperKey, "env", envVar, "error", err.Error())
			}
		}

		viperConfigSet := viper.IsSet(viperKey)
		if !flag.Changed && viperConfigSet {
			val := viper.Get(viperKey)

			err := getClientCertificateCmd.Flags().Set(flag.Name, fmt.Sprintf("%v", val))
			if err != nil {
				logger.Info("Failed to set flag", "flag", flag.Name, "error", err.Error())
			}
		}
	})
}

// addKlogFlags adds flags from k8s.io/klog.
func addKlogFlags(fs *pflag.FlagSet) {
	local := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	klog.InitFlags(local)

	local.VisitAll(func(fl *flag.Flag) {
		fs.AddGoFlag(fl)
	})
}

func readInConfig() error {
	origErr := viper.ReadInConfig()
	if origErr == nil {
		return nil
	}

	if _, ok := origErr.(viper.ConfigFileNotFoundError); ok { // fallback to gardenctl-v2 config
		addGardenctlV2Config()

		err := viper.ReadInConfig()
		if err == nil {
			return nil
		}

		if _, ok := origErr.(viper.ConfigFileNotFoundError); ok {
			return origErr
		}

		return fmt.Errorf("failed to fallback to gardenctl-v2 config file: %w", err)
	}

	return origErr
}

func addGardenctlV2Config() {
	const (
		envPrefix        = "GCTL"
		envGardenHomeDir = envPrefix + "_HOME"
		envConfigName    = envPrefix + "_CONFIG_NAME"

		gardenHomeFolder = ".garden"
		configName       = "gardenctl-v2"
	)

	// Find home directory.
	home, err := homedir.Dir()
	cobra.CheckErr(err)

	configPath := filepath.Join(home, gardenHomeFolder)

	// Search config in ~/.garden or in path provided with the env variable GCTL_HOME with name "gardenctl-v2" (without extension) or name from env variable GCTL_CONFIG_NAME.
	envHomeDir, err := homedir.Expand(os.Getenv(envGardenHomeDir))
	cobra.CheckErr(err)

	viper.AddConfigPath(envHomeDir)
	viper.AddConfigPath(configPath)

	if os.Getenv(envConfigName) != "" {
		viper.SetConfigName(os.Getenv(envConfigName))
	} else {
		viper.SetConfigName(configName)
	}
}
