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
	"crypto/x509"
	"fmt"
	"reflect"

	gardencorev1alpha1helper "github.com/gardener/gardener/pkg/apis/core/v1alpha1/helper"
	"github.com/gardener/gardener/pkg/utils"
	"github.com/gardener/gardener/pkg/utils/infodata"
	"github.com/gardener/gardener/pkg/utils/secrets"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Comparator interface {
	Compare(name string, fromShootState, fromControlPlane infodata.InfoData) (bool, error)
}

type caComparator struct {
	logger logr.Logger
}

func NewCAComparator(logger logr.Logger) Comparator {
	return &caComparator{logger}
}

func (c *caComparator) Compare(name string, fromShootState, fromControlPlane infodata.InfoData) (bool, error) {
	if fromShootState == nil || fromShootState == infodata.EmptyInfoData {
		// if the secret does not exist in the gardenerResourceDataList then we can assume it is correct
		c.logger.V(1).Info("Secret not found in ShootState", "name", name)
		return true, nil
	}

	if fromControlPlane == nil || fromControlPlane == infodata.EmptyInfoData {
		// if the secret does not exist in the control plane then there is nothing to sync
		c.logger.V(1).Info("Secret not found in control plane", "name", name)
		return true, nil
	}

	return reflect.DeepEqual(fromShootState, fromControlPlane), nil
}

type secretsComparator struct {
	logger logr.Logger
}

func NewSecretsComparator(logger logr.Logger) Comparator {
	return &secretsComparator{logger}
}

func (c *secretsComparator) Compare(name string, fromShootState, fromControlPlane infodata.InfoData) (bool, error) {
	if fromShootState == nil || fromShootState == infodata.EmptyInfoData {
		// if the secret does not exist in the gardenerResourceDataList then we can assume it is correct
		c.logger.V(1).Info("Secret not found in ShootState", "name", name)
		return true, nil
	}

	if fromControlPlane == nil || fromControlPlane == infodata.EmptyInfoData {
		// if the secret does not exist in the control plane then there is nothing to sync
		c.logger.V(1).Info("Secret not found in control plane", "name", name)
		return true, nil
	}

	return reflect.DeepEqual(fromShootState, fromControlPlane), nil
}

type Verifier interface {
	Verify(caName, name string, certificateData []byte) (bool, error)
}

type certificateVerifier struct {
	logger         logr.Logger
	caCertificates map[string]*secrets.Certificate
}

func NewCertificateVerifier(logger logr.Logger, caCertificates map[string]*secrets.Certificate) Verifier {
	return &certificateVerifier{logger, caCertificates}
}

func (v *certificateVerifier) Verify(caName, name string, certificateData []byte) (bool, error) {
	cert, err := utils.DecodeCertificate(certificateData)
	if err != nil {
		return false, fmt.Errorf("Could not decode certificate %s: %w", name, err)
	}
	certPool := x509.NewCertPool()
	certPool.AddCert(v.caCertificates[caName].Certificate)
	opts := x509.VerifyOptions{
		Roots:     certPool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	chains, err := cert.Verify(opts)
	if err != nil {
		return false, fmt.Errorf("Could not verify certificate %s with CA %s, %w", name, caName, err)
	}
	if len(chains) > 0 {
		return true, nil
	}
	return false, nil
}

type Loader interface {
	Load(secretConfig secrets.ConfigInterface, existingSecret *corev1.Secret) (dataFromShootState, dataFromExistingSecret infodata.InfoData, err error)
}

type loader struct {
	logger                   logr.Logger
	gardenerResourceDataList gardencorev1alpha1helper.GardenerResourceDataList
}

func NewLoader(logger logr.Logger, gardenerResourceDataList gardencorev1alpha1helper.GardenerResourceDataList) Loader {
	return &loader{logger, gardenerResourceDataList}
}

func (l *loader) Load(secretConfig secrets.ConfigInterface, existingSecret *corev1.Secret) (dataFromShootState, dataFromExistingSecret infodata.InfoData, err error) {
	loader, ok := secretConfig.(infodata.Loader)
	if !ok {
		return nil, nil, fmt.Errorf("secretConfig for secret %s does not implement Loader interface", secretConfig.GetName())
	}
	dataFromExistingSecret, err = loader.LoadFromSecretData(existingSecret.Data)
	if err != nil {
		return nil, nil, err
	}
	dataFromShootState, err = infodata.GetInfoData(l.gardenerResourceDataList, secretConfig.GetName())
	if err != nil {
		return nil, nil, err
	}
	return
}

type Synchronizer interface {
	Sync(string, infodata.InfoData) error
	Delete(ctx context.Context, c client.Client, name, namespace string) error
	GetUpdatedResourceDataList() gardencorev1alpha1helper.GardenerResourceDataList
}

type synchronizer struct {
	logger                   logr.Logger
	gardenerResourceDataList gardencorev1alpha1helper.GardenerResourceDataList
}

func NewSynchronizer(logger logr.Logger, gardenerResourceDataList gardencorev1alpha1helper.GardenerResourceDataList) Synchronizer {
	return &synchronizer{logger, gardenerResourceDataList}
}

func (s *synchronizer) Sync(name string, data infodata.InfoData) error {
	return infodata.UpsertInfoData(&s.gardenerResourceDataList, name, data)
}

func (s *synchronizer) Delete(ctx context.Context, c client.Client, name, namespace string) error {
	if err := c.Delete(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace}}); client.IgnoreNotFound(err) != nil {
		return err
	}
	s.gardenerResourceDataList.Delete(name)
	return nil
}

func (s *synchronizer) GetUpdatedResourceDataList() gardencorev1alpha1helper.GardenerResourceDataList {
	return s.gardenerResourceDataList
}
