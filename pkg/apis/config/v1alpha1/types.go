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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	componentbaseconfig "k8s.io/component-base/config"
	"k8s.io/klog"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// SecretsCheckerConfiguration defines the configuration for the Secret Checker.
type SecretsCheckerConfiguration struct {
	metav1.TypeMeta `json:",inline"`
	// GardenClientConnection specifies the kubeconfig file and the client connection settings
	// for the proxy server to use when communicating with the garden apiserver.
	GardenClientConnection componentbaseconfig.ClientConnectionConfiguration `json:"gardenClientConnection"`
	// SeedClientConnection specifies the kubeconfig file and the client connection settings
	// for the proxy server to use when communicating with the seed apiserver.
	SeedClientConnection componentbaseconfig.ClientConnectionConfiguration `json:"seedClientConnection"`
	// Controllers defines the configuration of the controllers.
	Controllers SecretsCheckerControllerConfiguration `json:"controllers"`
	// LeaderElection defines the configuration of leader election client.
	LeaderElection *componentbaseconfig.LeaderElectionConfiguration `json:"leaderElection"`
	// LogLevel is the level/severity for the logs. Must be one of [info,debug,error].
	LogLevel string `json:"logLevel"`
	// LogFormat is the output format for the logs. Must be one of [text,json].
	LogFormat string `json:"logFormat"`
	// KubernetesLogLevel is the log level used for Kubernetes' k8s.io/klog functions.
	KubernetesLogLevel klog.Level `json:"kubernetesLogLevel"`
	// Debugging holds configuration for Debugging related features.
	Debugging *componentbaseconfig.DebuggingConfiguration `json:"debugging"`
}

// SecretsCheckerControllerConfiguration defines settings for the Secret Checker controller.
type SecretsCheckerControllerConfiguration struct {
	ShootSecrets *ShootSecretsControllerConfiguration `json:"shootSecrets"`
}

// ShootSecretsControllerConfiguration defines the configuration for the Shoot Secrets controller.
type ShootSecretsControllerConfiguration struct {
	// ConcurrentSyncs is the number of workers used for the controller to work on
	// events.
	ConcurrentSyncs int `json:"concurrentSyncs"`
}
