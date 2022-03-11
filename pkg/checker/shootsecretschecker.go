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

package checker

import (
	"context"
	"fmt"
	"time"

	gardencorev1alpha1 "github.com/gardener/gardener/pkg/apis/core/v1alpha1"
	gardencorev1alpha1helper "github.com/gardener/gardener/pkg/apis/core/v1alpha1/helper"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	shootpkg "github.com/gardener/gardener/pkg/operation/shoot"
	gutil "github.com/gardener/gardener/pkg/utils/gardener"
	"github.com/gardener/gardener/pkg/utils/secrets"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type ShootSecretsChecker struct {
	logger           logr.Logger
	gardenClient     client.Client
	seedClient       client.Client
	syncToShootState bool
	seedNamespace    string
	shoot            *gardencorev1beta1.Shoot
}

func NewShootSecretsChecker(logger logr.Logger, gardenClient client.Client, seedClient client.Client, shoot *gardencorev1beta1.Shoot) *ShootSecretsChecker {
	logger = logger.WithValues("shoot", client.ObjectKeyFromObject(shoot))
	return &ShootSecretsChecker{
		logger:       logger,
		gardenClient: gardenClient,
		seedClient:   seedClient,
		shoot:        shoot,
	}
}

func (c *ShootSecretsChecker) CheckSecrets(ctx context.Context) error {
	c.logger.V(1).Info("Checking secrets for shoot")

	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	seedNamespace, err := c.getSeedNamespace(ctx)
	if err != nil {
		return err
	}
	c.seedNamespace = seedNamespace

	existingSecretsMap, err := c.getExistingSecretsMap(ctx)
	if err != nil {
		return err
	}

	wantedCAConfigs := WantedCertificateAuthorities()
	existingCACertificates, err := c.loadCertificateAuthorities(wantedCAConfigs, existingSecretsMap)
	if err != nil {
		return err
	}
	wantedSecretConfigs, err := GenerateWantedSecretConfigs(existingCACertificates)
	if err != nil {
		return err
	}
	staticTokenConfig := GenerateStaticTokenConfig()

	wantedSecretConfigs = append(wantedSecretConfigs, staticTokenConfig, basicAuthSecretAPIServer)

	shootState := &gardencorev1alpha1.ShootState{}
	if err := c.gardenClient.Get(ctx, types.NamespacedName{Namespace: c.shoot.Namespace, Name: c.shoot.Name}, shootState); err != nil {
		return fmt.Errorf("Could not get shootstate: %v", err)
	}
	gardenerResourceDataList := gardencorev1alpha1helper.GardenerResourceDataList(shootState.Spec.Gardener).DeepCopy()

	caComparator := NewCAComparator(c.logger)
	secretsComparator := NewSecretsComparator(c.logger)
	verifier := NewCertificateVerifier(c.logger, existingCACertificates)

	loader := NewLoader(c.logger, gardenerResourceDataList.DeepCopy())
	synchronizer := NewSynchronizer(c.logger, gardenerResourceDataList.DeepCopy())

	if err := c.checkSecrets(ctx, &caCollection{wantedCAConfigs}, existingSecretsMap, caComparator, nil, loader, synchronizer); err != nil {
		return err
	}

	if err := c.checkSecrets(ctx, &secretCollections{wantedSecretConfigs}, existingSecretsMap, secretsComparator, verifier, loader, synchronizer); err != nil {
		return err
	}

	if c.syncToShootState {
		patch := client.MergeFromWithOptions(shootState.DeepCopy(), client.MergeFromWithOptimisticLock{})
		shootState.Spec.Gardener = synchronizer.GetUpdatedResourceDataList()
		if err := c.gardenClient.Patch(ctx, shootState, patch); err != nil {
			return err
		}
	}

	c.logger.V(1).Info("Finished checking secrets for shoot")
	return nil
}

func (c *ShootSecretsChecker) getExistingSecretsMap(ctx context.Context) (map[string]*corev1.Secret, error) {
	existingSecretList := &corev1.SecretList{}
	if err := c.seedClient.List(ctx, existingSecretList, client.InNamespace(c.seedNamespace)); err != nil {
		return nil, fmt.Errorf("Could not list secrets: %v", err)
	}
	secretListMap := make(map[string]*corev1.Secret, len(existingSecretList.Items))
	for _, secret := range existingSecretList.Items {
		secretObj := secret
		secretListMap[secret.Name] = &secretObj
	}
	return secretListMap, nil
}

func (c *ShootSecretsChecker) getSeedNamespace(ctx context.Context) (string, error) {
	project, err := gutil.ProjectForNamespaceFromReader(ctx, c.gardenClient, c.shoot.Namespace)
	if err != nil {
		return "", fmt.Errorf("error getting project: %v", err)
	}
	return shootpkg.ComputeTechnicalID(project.Name, c.shoot), nil
}

func (c *ShootSecretsChecker) loadCertificateAuthorities(wantedCAConfigs map[string]*secrets.CertificateSecretConfig, existingSecrets map[string]*corev1.Secret) (map[string]*secrets.Certificate, error) {
	loadedCAs := map[string]*secrets.Certificate{}
	for name, secret := range existingSecrets {
		_, ok := wantedCAConfigs[name]
		if !ok {
			continue
		}
		data, err := secrets.LoadCertificate(name, secret.Data[secrets.DataKeyPrivateKeyCA], secret.Data[secrets.DataKeyCertificateCA])
		if err != nil {
			return nil, fmt.Errorf("could not load certificate data form secret %s: %w", name, err)
		}
		loadedCAs[name] = data
	}
	return loadedCAs, nil
}

func (c *ShootSecretsChecker) checkSecrets(ctx context.Context, collection Collection, secretsMap map[string]*corev1.Secret, comparator Comparator, verifier Verifier, loader Loader, synchronizer Synchronizer) error {
	for name, secretConfig := range collection.Map() {
		secret, ok := secretsMap[name]
		if !ok {
			c.logger.V(1).Info("Could not find config for secret. Skipping check.", "name", name)
			continue
		}
		dataFromShootState, dataFromExistingSecret, err := loader.Load(secretConfig, secret)
		if err != nil {
			return err
		}

		secretVerified := true
		caName := ""
		if verifier != nil {
			switch v := secretConfig.(type) {
			case *secrets.CertificateSecretConfig:
				data, ok := dataFromExistingSecret.(*secrets.CertificateInfoData)
				caName = v.SigningCA.Name
				if ok {
					secretVerified, err = verifier.Verify(caName, name, data.Certificate)
				}
			case *secrets.ControlPlaneSecretConfig:
				data, ok := dataFromExistingSecret.(*secrets.CertificateInfoData)
				caName = v.SigningCA.Name
				if ok {
					secretVerified, err = verifier.Verify(caName, name, data.Certificate)
				}
			}
		}

		if !secretVerified {
			c.logger.V(0).Info("Certificate is not signed by CA found in shoot control plane namespace", "certificate", name, "ca", caName)
			if c.syncToShootState {
				c.logger.V(0).Info("Deleting secret from ShootState and control plane namespace so that it is regenerated properly", "name", name)
				if err := synchronizer.Delete(ctx, c.seedClient, name, c.seedNamespace); err != nil {
					return err
				}
			}
			continue
		}

		secretsMatch, err := comparator.Compare(name, dataFromShootState, dataFromExistingSecret)
		if err != nil {
			return err
		}

		if !secretsMatch {
			c.logger.V(0).Info("Secrets do not match", "name", name)
			if c.syncToShootState {
				c.logger.V(0).Info("Syncing secret to ShootState", "name", name)
				if err := synchronizer.Sync(name, dataFromExistingSecret); err != nil {
					return err
				}
			}
		}

	}
	return nil
}

type Collection interface {
	Map() map[string]secrets.ConfigInterface
}

type caCollection struct {
	caConfigs map[string]*secrets.CertificateSecretConfig
}

func (c *caCollection) Map() map[string]secrets.ConfigInterface {
	configs := make(map[string]secrets.ConfigInterface, len(c.caConfigs))
	for n, c := range c.caConfigs {
		configs[n] = c
	}
	return configs
}

type secretCollections struct {
	secretConfigs []secrets.ConfigInterface
}

func (c *secretCollections) Map() map[string]secrets.ConfigInterface {
	configs := make(map[string]secrets.ConfigInterface, len(c.secretConfigs))
	for _, c := range c.secretConfigs {
		configs[c.GetName()] = c
	}
	return configs
}
