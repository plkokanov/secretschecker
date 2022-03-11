// Copyright (c) 2020 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
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

package checker

import (
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	"github.com/gardener/gardener/pkg/operation/botanist/component/etcd"
	"github.com/gardener/gardener/pkg/operation/botanist/component/kubeapiserver"
	"github.com/gardener/gardener/pkg/operation/botanist/component/kubecontrollermanager"
	"github.com/gardener/gardener/pkg/operation/botanist/component/kubescheduler"
	"github.com/gardener/gardener/pkg/operation/botanist/component/metricsserver"
	"github.com/gardener/gardener/pkg/operation/botanist/component/resourcemanager"
	"github.com/gardener/gardener/pkg/operation/botanist/component/vpnseedserver"
	"github.com/gardener/gardener/pkg/operation/botanist/component/vpnshoot"
	"github.com/gardener/gardener/pkg/operation/common"
	"github.com/gardener/gardener/pkg/utils/secrets"

	"k8s.io/apiserver/pkg/authentication/user"
)

var basicAuthSecretAPIServer = &secrets.BasicAuthSecretConfig{
	Name:           kubeapiserver.SecretNameBasicAuth,
	Format:         secrets.BasicAuthFormatCSV,
	Username:       "admin",
	PasswordLength: 32,
}

func WantedCertificateAuthorities() map[string]*secrets.CertificateSecretConfig {
	wantedCertificateAuthorities := map[string]*secrets.CertificateSecretConfig{
		v1beta1constants.SecretNameCACluster: {
			Name:       v1beta1constants.SecretNameCACluster,
			CommonName: "kubernetes",
			CertType:   secrets.CACert,
		},
		v1beta1constants.SecretNameCAETCD: {
			Name:       etcd.SecretNameCA,
			CommonName: "etcd",
			CertType:   secrets.CACert,
		},
		v1beta1constants.SecretNameCAFrontProxy: {
			Name:       v1beta1constants.SecretNameCAFrontProxy,
			CommonName: "front-proxy",
			CertType:   secrets.CACert,
		},
		v1beta1constants.SecretNameCAKubelet: {
			Name:       v1beta1constants.SecretNameCAKubelet,
			CommonName: "kubelet",
			CertType:   secrets.CACert,
		},
		v1beta1constants.SecretNameCAMetricsServer: {
			Name:       metricsserver.SecretNameCA,
			CommonName: "metrics-server",
			CertType:   secrets.CACert,
		},
		v1beta1constants.SecretNameCAVPN: {
			Name:       v1beta1constants.SecretNameCAVPN,
			CommonName: "vpn",
			CertType:   secrets.CACert,
		},
	}

	return wantedCertificateAuthorities
}

func GenerateStaticTokenConfig() *secrets.StaticTokenSecretConfig {
	return &secrets.StaticTokenSecretConfig{
		Name: kubeapiserver.SecretNameStaticToken,
		Tokens: map[string]secrets.TokenConfig{
			common.KubecfgUsername: {
				Username: common.KubecfgUsername,
				UserID:   common.KubecfgUsername,
				Groups:   []string{user.SystemPrivilegedGroup},
			},
			common.KubeAPIServerHealthCheck: {
				Username: common.KubeAPIServerHealthCheck,
				UserID:   common.KubeAPIServerHealthCheck,
			},
		},
	}
}

// GenerateWantedSecretConfigs returns a list of Secret configuration objects satisfying the secret config interface,
// each containing their specific configuration for the creation of certificates (server/client), RSA key pairs, basic
// authentication credentials, etc.
func GenerateWantedSecretConfigs(certificateAuthorities map[string]*secrets.Certificate) ([]secrets.ConfigInterface, error) {
	secretList := []secrets.ConfigInterface{
		&secrets.ControlPlaneSecretConfig{
			CertificateSecretConfig: &secrets.CertificateSecretConfig{
				Name:      kubeapiserver.SecretNameServer,
				CertType:  secrets.ServerCert,
				SigningCA: certificateAuthorities[v1beta1constants.SecretNameCACluster],
			},
		},
		// Secret definition for kube-apiserver to kubelets communication
		&secrets.ControlPlaneSecretConfig{
			CertificateSecretConfig: &secrets.CertificateSecretConfig{
				Name:      kubeapiserver.SecretNameKubeAPIServerToKubelet,
				CertType:  secrets.ClientCert,
				SigningCA: certificateAuthorities[v1beta1constants.SecretNameCAKubelet],
			},
		},

		// Secret definition for kube-aggregator
		&secrets.ControlPlaneSecretConfig{
			CertificateSecretConfig: &secrets.CertificateSecretConfig{
				Name:      kubeapiserver.SecretNameKubeAggregator,
				CertType:  secrets.ClientCert,
				SigningCA: certificateAuthorities[v1beta1constants.SecretNameCAFrontProxy],
			},
		},

		// Secret definition for kube-controller-manager server
		&secrets.ControlPlaneSecretConfig{
			CertificateSecretConfig: &secrets.CertificateSecretConfig{
				Name:      kubecontrollermanager.SecretNameServer,
				CertType:  secrets.ServerCert,
				SigningCA: certificateAuthorities[v1beta1constants.SecretNameCACluster],
			},
		},

		// Secret definition for kube-scheduler server
		&secrets.ControlPlaneSecretConfig{
			CertificateSecretConfig: &secrets.CertificateSecretConfig{
				Name:      kubescheduler.SecretNameServer,
				CertType:  secrets.ServerCert,
				SigningCA: certificateAuthorities[v1beta1constants.SecretNameCACluster],
			},
		},

		// Secret definition for gardener-resource-manager server
		&secrets.CertificateSecretConfig{
			Name:      resourcemanager.SecretNameServer,
			CertType:  secrets.ServerCert,
			SigningCA: certificateAuthorities[v1beta1constants.SecretNameCACluster],
		},

		// Secret definition for prometheus
		// TODO(rfranzke): Delete this in a future release once all monitoring configurations of extensions have been
		// adapted.
		&secrets.ControlPlaneSecretConfig{
			CertificateSecretConfig: &secrets.CertificateSecretConfig{
				Name:      "prometheus",
				CertType:  secrets.ClientCert,
				SigningCA: certificateAuthorities[v1beta1constants.SecretNameCACluster],
			},
		},

		// Secret definition for prometheus to kubelets communication
		&secrets.ControlPlaneSecretConfig{
			CertificateSecretConfig: &secrets.CertificateSecretConfig{
				Name:      "prometheus-kubelet",
				CertType:  secrets.ClientCert,
				SigningCA: certificateAuthorities[v1beta1constants.SecretNameCAKubelet],
			},
		},

		// Secret definition for monitoring
		&secrets.BasicAuthSecretConfig{
			Name:   common.MonitoringIngressCredentials,
			Format: secrets.BasicAuthFormatNormal,

			Username:       "admin",
			PasswordLength: 32,
		},

		// Secret definition for monitoring for shoot owners
		&secrets.BasicAuthSecretConfig{
			Name:   common.MonitoringIngressCredentialsUsers,
			Format: secrets.BasicAuthFormatNormal,

			Username:       "admin",
			PasswordLength: 32,
		},

		// Secret definition for ssh-keypair
		&secrets.RSASecretConfig{
			Name:       v1beta1constants.SecretNameSSHKeyPair,
			Bits:       4096,
			UsedForSSH: true,
		},

		// Secret definition for service-account-key
		&secrets.RSASecretConfig{
			Name:       v1beta1constants.SecretNameServiceAccountKey,
			Bits:       4096,
			UsedForSSH: false,
		},

		// Secret definition for etcd server
		&secrets.CertificateSecretConfig{
			Name:      etcd.SecretNameServer,
			CertType:  secrets.ServerClientCert,
			SigningCA: certificateAuthorities[v1beta1constants.SecretNameCAETCD],
		},

		// Secret definition for etcd server
		&secrets.CertificateSecretConfig{
			Name:      etcd.SecretNameClient,
			CertType:  secrets.ClientCert,
			SigningCA: certificateAuthorities[v1beta1constants.SecretNameCAETCD],
		},

		// Secret definition for metrics-server
		&secrets.CertificateSecretConfig{
			Name:      metricsserver.SecretNameServer,
			CertType:  secrets.ServerClientCert,
			SigningCA: certificateAuthorities[v1beta1constants.SecretNameCAMetricsServer],
		},

		// Secret definition for alertmanager (ingress)
		&secrets.CertificateSecretConfig{
			Name:      common.AlertManagerTLS,
			CertType:  secrets.ServerCert,
			SigningCA: certificateAuthorities[v1beta1constants.SecretNameCACluster],
		},

		// Secret definition for grafana (ingress)
		&secrets.CertificateSecretConfig{
			Name:      common.GrafanaTLS,
			CertType:  secrets.ServerCert,
			SigningCA: certificateAuthorities[v1beta1constants.SecretNameCACluster],
		},

		// Secret definition for prometheus (ingress)
		&secrets.CertificateSecretConfig{
			Name:      common.PrometheusTLS,
			CertType:  secrets.ServerCert,
			SigningCA: certificateAuthorities[v1beta1constants.SecretNameCACluster],
		},

		&secrets.ControlPlaneSecretConfig{
			CertificateSecretConfig: &secrets.CertificateSecretConfig{
				Name:      common.KubecfgSecretName,
				SigningCA: certificateAuthorities[v1beta1constants.SecretNameCACluster],
			},
		},

		// Secret definition for loki (ingress)
		&secrets.CertificateSecretConfig{
			Name:      common.LokiTLS,
			CertType:  secrets.ServerCert,
			SigningCA: certificateAuthorities[v1beta1constants.SecretNameCACluster],
		},

		// Secret definitions for dependency-watchdog-internal and external probes
		&secrets.ControlPlaneSecretConfig{
			CertificateSecretConfig: &secrets.CertificateSecretConfig{
				Name:      kubeapiserver.DependencyWatchdogInternalProbeSecretName,
				CertType:  secrets.ClientCert,
				SigningCA: certificateAuthorities[v1beta1constants.SecretNameCACluster],
			},
		}, &secrets.ControlPlaneSecretConfig{
			CertificateSecretConfig: &secrets.CertificateSecretConfig{
				Name:      kubeapiserver.DependencyWatchdogExternalProbeSecretName,
				CertType:  secrets.ClientCert,
				SigningCA: certificateAuthorities[v1beta1constants.SecretNameCACluster],
			},
		},

		// Secret definition for vpn-shoot (OpenVPN client side)
		&secrets.CertificateSecretConfig{
			Name:      vpnshoot.SecretNameVPNShootClient,
			CertType:  secrets.ClientCert,
			SigningCA: certificateAuthorities[v1beta1constants.SecretNameCAVPN],
		},

		// Secret definition for vpn-seed-server (OpenVPN server side)
		&secrets.CertificateSecretConfig{
			Name:      "vpn-seed-server",
			CertType:  secrets.ServerCert,
			SigningCA: certificateAuthorities[v1beta1constants.SecretNameCAVPN],
		},

		&secrets.VPNTLSAuthConfig{
			Name: vpnseedserver.VpnSeedServerTLSAuth,
		},

		// Secret definition for kube-apiserver http proxy client
		&secrets.CertificateSecretConfig{
			Name:      kubeapiserver.SecretNameHTTPProxy,
			CertType:  secrets.ClientCert,
			SigningCA: certificateAuthorities[v1beta1constants.SecretNameCAVPN],
		},

		// Secret definition for vpn-shoot (OpenVPN server side)
		&secrets.CertificateSecretConfig{
			Name:      vpnshoot.SecretNameVPNShoot,
			CertType:  secrets.ServerCert,
			SigningCA: certificateAuthorities[v1beta1constants.SecretNameCACluster],
		},

		// Secret definition for vpn-seed (OpenVPN client side)
		&secrets.CertificateSecretConfig{
			Name:      kubeapiserver.SecretNameVPNSeed,
			CertType:  secrets.ClientCert,
			SigningCA: certificateAuthorities[v1beta1constants.SecretNameCACluster],
		},

		&secrets.VPNTLSAuthConfig{
			Name: kubeapiserver.SecretNameVPNSeedTLSAuth,
		},

		&secrets.CertificateSecretConfig{
			Name:      common.VPASecretName,
			CertType:  secrets.ServerCert,
			SigningCA: certificateAuthorities[v1beta1constants.SecretNameCACluster],
		},
	}

	return secretList, nil
}
