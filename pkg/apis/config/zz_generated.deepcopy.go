//go:build !ignore_autogenerated
// +build !ignore_autogenerated

/*
Copyright (c) SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
// Code generated by deepcopy-gen. DO NOT EDIT.

package config

import (
	runtime "k8s.io/apimachinery/pkg/runtime"
	componentbaseconfig "k8s.io/component-base/config"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *SecretsCheckerConfiguration) DeepCopyInto(out *SecretsCheckerConfiguration) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	out.GardenClientConnection = in.GardenClientConnection
	out.SeedClientConnection = in.SeedClientConnection
	in.Controllers.DeepCopyInto(&out.Controllers)
	if in.LeaderElection != nil {
		in, out := &in.LeaderElection, &out.LeaderElection
		*out = new(componentbaseconfig.LeaderElectionConfiguration)
		**out = **in
	}
	if in.Debugging != nil {
		in, out := &in.Debugging, &out.Debugging
		*out = new(componentbaseconfig.DebuggingConfiguration)
		**out = **in
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new SecretsCheckerConfiguration.
func (in *SecretsCheckerConfiguration) DeepCopy() *SecretsCheckerConfiguration {
	if in == nil {
		return nil
	}
	out := new(SecretsCheckerConfiguration)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *SecretsCheckerConfiguration) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *SecretsCheckerControllerConfiguration) DeepCopyInto(out *SecretsCheckerControllerConfiguration) {
	*out = *in
	if in.ShootSecrets != nil {
		in, out := &in.ShootSecrets, &out.ShootSecrets
		*out = new(ShootSecretsControllerConfiguration)
		**out = **in
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new SecretsCheckerControllerConfiguration.
func (in *SecretsCheckerControllerConfiguration) DeepCopy() *SecretsCheckerControllerConfiguration {
	if in == nil {
		return nil
	}
	out := new(SecretsCheckerControllerConfiguration)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ShootSecretsControllerConfiguration) DeepCopyInto(out *ShootSecretsControllerConfiguration) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ShootSecretsControllerConfiguration.
func (in *ShootSecretsControllerConfiguration) DeepCopy() *ShootSecretsControllerConfiguration {
	if in == nil {
		return nil
	}
	out := new(ShootSecretsControllerConfiguration)
	in.DeepCopyInto(out)
	return out
}
