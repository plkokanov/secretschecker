// Copyright (c) 2022 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package app

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/go-logr/logr"
	"github.com/plkokanov/secretschecker/pkg/apis/config"
	configv1alpha1 "github.com/plkokanov/secretschecker/pkg/apis/config/v1alpha1"
	"github.com/plkokanov/secretschecker/pkg/checker"
	"github.com/plkokanov/secretschecker/pkg/clientprovider"

	"github.com/gardener/gardener/pkg/client/kubernetes/clientmap"
	clientmapbuilder "github.com/gardener/gardener/pkg/client/kubernetes/clientmap/builder"
	"github.com/gardener/gardener/pkg/logger"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"k8s.io/component-base/version"
	"k8s.io/component-base/version/verflag"
)

type Options struct {
	// ConfigFile is the location of the Gardenlet's configuration file.
	ConfigFile       string
	SyncToShootState bool
	config           *config.SecretsCheckerConfiguration
	scheme           *runtime.Scheme
	Shoot            string
	Namespace        string
	codecs           serializer.CodecFactory
}

func NewOptions() (*Options, error) {
	o := &Options{
		config: &config.SecretsCheckerConfiguration{},
	}

	o.scheme = runtime.NewScheme()
	o.codecs = serializer.NewCodecFactory(o.scheme)

	if err := config.AddToScheme(o.scheme); err != nil {
		return nil, err
	}

	if err := configv1alpha1.AddToScheme(o.scheme); err != nil {
		return nil, err
	}

	return o, nil
}

func (o *Options) AddFlags(fs *pflag.FlagSet) {
	fs.StringVar(&o.ConfigFile, "config", o.ConfigFile, "The path to the configuration file.")
	fs.BoolVar(&o.SyncToShootState, "sync-to-shootstate", o.SyncToShootState, "This flag determines whether to sync the secrets from the shoot's namespace in the seed to the ShootState")
	fs.StringVar(&o.Shoot, "shoot", o.Shoot, "Specifies the secrets of which shoot should be checked for consistency")
	fs.StringVar(&o.Namespace, "namespace", o.Namespace, "Specifies the namespace in which to look for shoots")
}

func (o *Options) loadConfigFromFile(file string) (*config.SecretsCheckerConfiguration, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}

	return o.decodeConfig(data)
}

func (o *Options) decodeConfig(data []byte) (*config.SecretsCheckerConfiguration, error) {
	secretsCheckerConfig := &config.SecretsCheckerConfiguration{}
	if _, _, err := o.codecs.UniversalDecoder().Decode(data, nil, secretsCheckerConfig); err != nil {
		return nil, err
	}

	return secretsCheckerConfig, nil
}

// Validate validates all the required options.
func (o *Options) validate(args []string) error {
	if len(args) != 0 {
		return errors.New("arguments are not supported")
	}

	return nil
}

func (o *Options) validateShootName() error {
	if o.Shoot != "" && o.Namespace == "" {
		return errors.New("--namespace flag must be specified when specifying shoot name")
	}
	return nil
}

func (o *Options) configFileSpecified() error {
	if len(o.ConfigFile) == 0 {
		return fmt.Errorf("missing secrets controller config file")
	}
	return nil
}

func (o *Options) run(ctx context.Context) error {
	if len(o.ConfigFile) > 0 {
		c, err := o.loadConfigFromFile(o.ConfigFile)
		if err != nil {
			return err
		}
		o.config = c
	}

	secretsChecker, err := NewSecretsChecker(ctx, o)
	if err != nil {
		return err
	}

	return secretsChecker.Execute(ctx)
}

func NewCommandStartSecretsChecker() *cobra.Command {
	opts, err := NewOptions()
	if err != nil {
		panic(err)
	}

	cmd := &cobra.Command{
		Use:   "checksecrets",
		Short: "Check the consistency of secrets",
		Long:  `Checks if the secrets in the ShootStates of all Shoots match those in Shoots' the control planes`,
		RunE: func(cmd *cobra.Command, args []string) error {
			verflag.PrintAndExitIfRequested()

			if err := opts.configFileSpecified(); err != nil {
				return err
			}
			if err := opts.validateShootName(); err != nil {
				return err
			}
			if err := opts.validate(args); err != nil {
				return err
			}
			return opts.run(cmd.Context())
		},
		SilenceUsage: true,
	}

	flags := cmd.Flags()
	verflag.AddFlags(flags)
	opts.AddFlags(flags)
	return cmd
}

type SecretsChecker struct {
	Config           *config.SecretsCheckerConfiguration
	SyncToShootState bool
	Shoot            string
	Namespace        string
	ClientMap        clientmap.ClientMap
	Log              logr.Logger
}

func NewSecretsChecker(ctx context.Context, opts *Options) (*SecretsChecker, error) {
	cfg := opts.config
	if cfg == nil {
		return nil, errors.New("config is required")
	}

	log, err := logger.NewZapLogger(cfg.LogLevel, cfg.LogFormat)
	if err != nil {
		return nil, fmt.Errorf("error instantiating zap logger: %w", err)
	}

	log.Info("Starting secrets checker", "version", version.Get())

	if flag := flag.Lookup("v"); flag != nil {
		if err := flag.Value.Set(fmt.Sprintf("%d", cfg.KubernetesLogLevel)); err != nil {
			return nil, err
		}
	}

	// Prepare a Kubernetes client object for the Garden cluster which contains all the Clientsets
	// that can be used to access the Kubernetes API.
	if kubeconfig := os.Getenv("KUBECONFIG"); kubeconfig != "" {
		cfg.GardenClientConnection.Kubeconfig = kubeconfig
	}

	clientConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		&clientcmd.ClientConfigLoadingRules{ExplicitPath: cfg.GardenClientConnection.Kubeconfig},
		&clientcmd.ConfigOverrides{ClusterInfo: clientcmdapi.Cluster{Server: ""}},
	)

	restCfg, err := clientConfig.ClientConfig()
	if err != nil {
		return nil, err
	}

	restCfg.Burst = int(cfg.GardenClientConnection.Burst)
	restCfg.QPS = cfg.GardenClientConnection.QPS
	restCfg.AcceptContentTypes = cfg.GardenClientConnection.AcceptContentTypes
	restCfg.ContentType = cfg.GardenClientConnection.ContentType

	gardenClientMapBuilder := clientmapbuilder.NewGardenClientMapBuilder().
		WithRESTConfig(restCfg)

	clientMap, err := clientmapbuilder.NewDelegatingClientMapBuilder().
		WithGardenClientMapBuilder(gardenClientMapBuilder).
		Build()
	if err != nil {
		return nil, fmt.Errorf("failed to build ClientMap: %w", err)
	}

	return &SecretsChecker{
		Config:           cfg,
		SyncToShootState: opts.SyncToShootState,
		Shoot:            opts.Shoot,
		Namespace:        opts.Namespace,
		Log:              log,
		ClientMap:        clientMap,
	}, nil
}

func (s *SecretsChecker) Execute(ctx context.Context) error {
	return checker.NewChecker(
		s.Config,
		s.SyncToShootState,
		s.Shoot,
		s.Namespace,
		clientprovider.DefaultSeedClientProviderFactory,
		s.ClientMap,
		s.Log).Execute(ctx)
}
