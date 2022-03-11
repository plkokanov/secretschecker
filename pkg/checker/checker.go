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
	"sync"

	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	"github.com/gardener/gardener/pkg/client/kubernetes/clientmap"
	"github.com/gardener/gardener/pkg/client/kubernetes/clientmap/keys"
	"github.com/go-logr/logr"
	"github.com/plkokanov/secretschecker/pkg/apis/config"
	"github.com/plkokanov/secretschecker/pkg/clientprovider"
)

type Checker struct {
	Config             *config.SecretsCheckerConfiguration
	SyncToShootState   bool
	ClientMap          clientmap.ClientMap
	SeedClientProvider clientprovider.SeedClientProviderFactory
	Log                logr.Logger
	shootQueue         chan *gardencorev1beta1.Shoot
}

func NewChecker(cfg *config.SecretsCheckerConfiguration, syncToShootState bool, clientProviderFactory clientprovider.SeedClientProviderFactory, clientMap clientmap.ClientMap, log logr.Logger) *Checker {
	return &Checker{
		Config:             cfg,
		SyncToShootState:   syncToShootState,
		ClientMap:          clientMap,
		SeedClientProvider: clientProviderFactory,
		Log:                log,
	}
}

func (c *Checker) Execute(ctx context.Context) error {
	gardenClient, err := c.ClientMap.GetClient(ctx, keys.ForGarden())
	if err != nil {
		return fmt.Errorf("could not get client to garden cluster: %w", err)
	}

	shootList := &gardencorev1beta1.ShootList{}
	if err := gardenClient.Client().List(ctx, shootList); err != nil {
		return err
	}
	shootQueue := make(chan gardencorev1beta1.Shoot, len(shootList.Items))
	for _, shoot := range shootList.Items {
		shootQueue <- shoot
	}
	seedClientProvider := c.SeedClientProvider.New(c.ClientMap)

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
					seedClient, err := seedClientProvider.GetClient(ctx, *shoot.Spec.SeedName)
					if err != nil {
						errorChan <- err
						continue
					}
					shootSecretsChecker := NewShootSecretsChecker(c.Log, gardenClient.Client(), seedClient.Client(), c.SyncToShootState, shoot.DeepCopy())
					if err := shootSecretsChecker.CheckSecrets(ctx); err != nil {
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
