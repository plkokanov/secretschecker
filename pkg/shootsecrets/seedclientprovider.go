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
	"fmt"
	"sync"

	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	"github.com/gardener/gardener/pkg/client/kubernetes"
	"github.com/gardener/gardener/pkg/client/kubernetes/clientmap"
	"github.com/gardener/gardener/pkg/client/kubernetes/clientmap/keys"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type SeedClientProvider interface {
	GetClient(context.Context, string) (kubernetes.Interface, error)
}

type SeedClientProviderFactory interface {
	New(clientmap.ClientMap) SeedClientProvider
}

type SeedClientProviderCreatorFunc func(cleintMap clientmap.ClientMap) SeedClientProvider

func (f SeedClientProviderCreatorFunc) New(clientMap clientmap.ClientMap) SeedClientProvider {
	return f(clientMap)
}

type seedClientProvider struct {
	clientMap   clientmap.ClientMap
	seedClients map[string]kubernetes.Interface
	lock        sync.RWMutex
}

func NewDefaultSeedClientProvider(clientMap clientmap.ClientMap) *seedClientProvider {
	return &seedClientProvider{
		clientMap:   clientMap,
		seedClients: map[string]kubernetes.Interface{},
	}
}

func (s *seedClientProvider) GetClient(ctx context.Context, seedName string) (kubernetes.Interface, error) {
	seedClient, found := func() (kubernetes.Interface, bool) {
		s.lock.RLock()
		defer s.lock.RUnlock()
		client, ok := s.seedClients[seedName]
		return client, ok
	}()

	if found {
		return seedClient, nil
	}

	gardenClient, err := s.clientMap.GetClient(ctx, keys.ForGarden())
	if err != nil {
		return nil, err
	}

	seed := &gardencorev1beta1.Seed{
		ObjectMeta: metav1.ObjectMeta{
			Name: seedName,
		},
	}
	if err := gardenClient.Client().Get(ctx, client.ObjectKeyFromObject(seed), seed); err != nil {
		return nil, fmt.Errorf("error geting seed: %v", client.ObjectKeyFromObject(seed))
	}

	seedSecretRef := seed.Spec.SecretRef
	seedSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      seedSecretRef.Name,
			Namespace: seedSecretRef.Namespace,
		},
	}
	if err := gardenClient.Client().Get(ctx, client.ObjectKeyFromObject(seedSecret), seedSecret); err != nil {
		return nil, fmt.Errorf("error getting seed secret: %v", client.ObjectKeyFromObject(seedSecret))
	}

	client, err := kubernetes.NewClientFromSecret(ctx, gardenClient.Client(), seedSecretRef.Namespace, seedSecretRef.Name,
		kubernetes.WithClientOptions(client.Options{
			Scheme: kubernetes.SeedScheme,
		}),
	)
	if err != nil {
		return nil, err
	}

	seedClient = func() kubernetes.Interface {
		s.lock.Lock()
		defer s.lock.Unlock()
		_, ok := s.seedClients[seedName]
		if !ok {
			s.seedClients[seedName] = client
		}
		return s.seedClients[seedName]
	}()

	return seedClient, nil
}
