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

package shootsecrets

import (
	"context"
	"encoding/base64"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"time"

	gardencorev1alpha1 "github.com/gardener/gardener/pkg/apis/core/v1alpha1"
	gardencorev1alpha1helper "github.com/gardener/gardener/pkg/apis/core/v1alpha1/helper"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"

	"github.com/gardener/gardener/pkg/client/kubernetes/clientmap"
	"github.com/gardener/gardener/pkg/client/kubernetes/clientmap/keys"
	shootpkg "github.com/gardener/gardener/pkg/operation/shoot"
	gutil "github.com/gardener/gardener/pkg/utils/gardener"
	"github.com/gardener/gardener/pkg/utils/infodata"
	"github.com/gardener/gardener/pkg/utils/secrets"
	"github.com/go-logr/logr"
	"github.com/plkokanov/secretschecker/pkg/apis/config"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Checker struct {
	Config             *config.SecretsCheckerConfiguration
	ClientMap          clientmap.ClientMap
	SeedClientProvider SeedClientProvider
	Log                logr.Logger
	shootQueue         chan *gardencorev1beta1.Shoot
}

func NewChecker(cfg *config.SecretsCheckerConfiguration, clientProviderFactory SeedClientProviderFactory, clientMap clientmap.ClientMap, log logr.Logger) *Checker {
	return &Checker{
		Config:             cfg,
		ClientMap:          clientMap,
		SeedClientProvider: clientProviderFactory.New(clientMap),
		Log:                log,
	}
}

func (c *Checker) Execute(ctx context.Context) error {
	gardenClient, err := c.ClientMap.GetClient(ctx, keys.ForGarden())
	if err != nil {
		return err
	}

	shootList := &gardencorev1beta1.ShootList{}
	if err := gardenClient.Client().List(ctx, shootList); err != nil {
		return err
	}
	shootQueue := make(chan gardencorev1beta1.Shoot, len(shootList.Items))
	for _, shoot := range shootList.Items {
		shootQueue <- shoot
	}

	c.Log.V(0).Info("Starting workers...")
	wg := sync.WaitGroup{}
	errorChan := make(chan error)
	for i := 0; i < c.Config.Controllers.ShootSecrets.ConcurrentSyncs; i++ {
		wg.Add(1)
		go func(ctx context.Context) {
			defer wg.Done()
			for {
				select {
				case shoot := <-shootQueue:
					if err := c.checkSecrets(ctx, shoot); err != nil {
						errorChan <- err
					}
				default:
					return
				}
			}
		}(ctx)
	}

	go func() {
		wg.Wait()
		close(errorChan)
	}()

	errorList := []error{}
	for err := range errorChan {
		errorList = append(errorList, err)
	}

	c.Log.V(0).Info("Stopping")
	if len(errorList) > 0 {
		return fmt.Errorf("errors occurred during secrets check %+v", errorList)
	}
	return nil
}

func (c *Checker) checkSecrets(ctx context.Context, shoot gardencorev1beta1.Shoot) error {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	shootLog := c.Log.WithValues("shoot", client.ObjectKeyFromObject(&shoot))

	shootLog.V(1).Info("Checking secrets for shoot")
	seedName := shoot.Spec.SeedName
	if seedName == nil {
		return fmt.Errorf("shoot %s is not assigned to seed", shoot.Name)
	}

	gardenClient, err := c.ClientMap.GetClient(ctx, keys.ForGarden())
	if err != nil {
		return fmt.Errorf("error getting garden client: %v", err)
	}

	project, err := gutil.ProjectForNamespaceFromReader(ctx, gardenClient.APIReader(), shoot.Namespace)
	if err != nil {
		return fmt.Errorf("error getting project: %v", err)
	}
	controlPlaneName := shootpkg.ComputeTechnicalID(project.Name, &shoot)

	seedClient, err := c.SeedClientProvider.GetClient(ctx, *seedName)
	if err != nil {
		return fmt.Errorf("error while getting seed client %v", err)
	}

	secretList := &corev1.SecretList{}
	if err := seedClient.Client().List(ctx, secretList, client.InNamespace(controlPlaneName)); err != nil {
		return fmt.Errorf("Could not list secrets: %v", err)
	}

	secretListMap := make(map[string]*corev1.Secret, len(secretList.Items))
	certAuthorityMap := make(map[string]*corev1.Secret, len(secretList.Items))
	for _, secret := range secretList.Items {
		secretObj := secret
		secretListMap[secret.Name] = &secretObj
		if secret.Name == "ca" || strings.Contains(secret.Name, "ca-") || strings.Contains(secret.Name, "-ca") {
			certAuthorityMap[secret.Name] = &secretObj
		}
	}

	shootState := &gardencorev1alpha1.ShootState{}
	if err := gardenClient.Client().Get(ctx, types.NamespacedName{Namespace: shoot.Namespace, Name: shoot.Name}, shootState); err != nil {
		return fmt.Errorf("Could not get shootstate: %v", err)
	}
	gardenerResourceList := gardencorev1alpha1helper.GardenerResourceDataList(shootState.Spec.Gardener)

	for _, secretData := range gardenerResourceList {
		if _, ok := secretListMap[secretData.Name]; !ok {
			continue
		}

		infoData, err := infodata.Unmarshal(&secretData)
		if err != nil {
			return err
		}
		var result bool
		switch infoData.(type) {
		case *secrets.CertificateInfoData:
			result = compareCertificateInfoData(infoData.(*secrets.CertificateInfoData), secretListMap[secretData.Name].Data, certAuthorityMap, secretData.Name)
		case *secrets.BasicAuthInfoData:
			result = compareBasicAuthInfoData(infoData.(*secrets.BasicAuthInfoData), secretListMap[secretData.Name].Data, secretData.Name, shootLog)
		case *secrets.PrivateKeyInfoData:
			result = comparePrivateKeyInfoData(infoData.(*secrets.PrivateKeyInfoData), secretListMap[secretData.Name].Data, secretData.Name)
		case *secrets.StaticTokenInfoData:
			result = compareStaticTokenInfoData(infoData.(*secrets.StaticTokenInfoData), secretListMap[secretData.Name].Data, secretData.Name)
		}
		if !result {
			shootLog.V(0).Info("Mismatch in secrets", "secret", secretData.Name)
		} else {
			shootLog.V(1).Info("Secrets match", "secret", secretData.Name)
		}
	}
	shootLog.V(1).Info("Finished checking secrets for shoot")
	return nil
}

func compareCertificateInfoData(certData *secrets.CertificateInfoData, secretData map[string][]byte, certificateAuthorities map[string]*corev1.Secret, secretName string) bool {
	return compareTLSSecret(certData, secretData, certificateAuthorities) ||
		compareOpaqueSecret(certData, secretData, certificateAuthorities, secretName) ||
		compareCASecret(certData, secretData)
}

func compareTLSSecret(certData *secrets.CertificateInfoData, secretData map[string][]byte, certificateAuthorities map[string]*corev1.Secret) bool {
	val1, ok1 := secretData["ca.crt"]
	val2, ok2 := secretData["tls.crt"]
	val3, ok3 := secretData["tls.key"]

	if !ok1 {
		return false
	}

	var caMatches bool
	for _, item := range certificateAuthorities {
		caMatches = reflect.DeepEqual(val1, item.Data["ca.crt"])
		if caMatches {
			break
		}
	}
	if !caMatches {
		return false
	}

	return ok2 && ok3 && reflect.DeepEqual(val2, certData.Certificate) && reflect.DeepEqual(val3, certData.PrivateKey)
}

func compareOpaqueSecret(certData *secrets.CertificateInfoData, secretData map[string][]byte, certificateAuthorities map[string]*corev1.Secret, secretName string) bool {
	val1, ok1 := secretData["ca.crt"]
	val2, ok2 := secretData[fmt.Sprintf("%s.crt", secretName)]
	val3, ok3 := secretData[fmt.Sprintf("%s.key", secretName)]
	_, ok4 := secretData["kubeconfig"]

	if !ok1 {
		return false
	}
	var caMatches bool
	for _, item := range certificateAuthorities {
		caMatches = reflect.DeepEqual(val1, item.Data["ca.crt"])
		if caMatches {
			break
		}
	}
	if !caMatches {

		return false
	}

	if ok4 {
		if ok2 && ok3 {
			return reflect.DeepEqual(val2, certData.Certificate) && reflect.DeepEqual(val3, certData.PrivateKey)
		}
		return true
	}

	return ok2 && ok3 && reflect.DeepEqual(val2, certData.Certificate) && reflect.DeepEqual(val3, certData.PrivateKey)
}

func compareCASecret(certData *secrets.CertificateInfoData, secretData map[string][]byte) bool {
	val1, ok1 := secretData["ca.crt"]
	val2, ok2 := secretData["ca.key"]

	return ok1 && ok2 && reflect.DeepEqual(val1, certData.Certificate) && reflect.DeepEqual(val2, certData.PrivateKey)
}

func compareBasicAuthInfoData(basicAuth *secrets.BasicAuthInfoData, secretData map[string][]byte, secretName string, log logr.Logger) bool {
	return reflect.DeepEqual([]byte(basicAuth.Password), secretData["password"]) || len(secretData["password"]) == 0
}

func comparePrivateKeyInfoData(privateKey *secrets.PrivateKeyInfoData, secretData map[string][]byte, secretName string) bool {
	var data []byte
	if val, ok := secretData["id_rsa"]; ok {
		data = val
	}
	if val, ok := secretData["vpn.tlsauth"]; ok {
		data = val
	}
	return reflect.DeepEqual(privateKey.PrivateKey, data)
}

func compareStaticTokenInfoData(staticToken *secrets.StaticTokenInfoData, secretData map[string][]byte, secretName string) bool {
	val, ok := secretData["token"]
	var tokenFound bool
	if !ok {
		return true
	}
	var decodedVal []byte
	_, err := base64.StdEncoding.Decode(decodedVal, val)
	if err != nil {
		fmt.Printf("Could not decode static token: %v", err)
		return false
	}
	for _, token := range staticToken.Tokens {
		tokenFound = reflect.DeepEqual(token, decodedVal)
		if tokenFound {
			break
		}
	}
	return tokenFound
}
