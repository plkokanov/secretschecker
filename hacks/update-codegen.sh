#!/bin/bash
#
# Copyright (c) 2022 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


set -o errexit
set -o nounset
set -o pipefail

SCRIPT_ROOT=$(dirname "${BASH_SOURCE[0]}")/..
CODEGEN_PKG=${CODEGEN_PKG:-$(cd "${SCRIPT_ROOT}"; ls -d -1 ./vendor/k8s.io/code-generator 2>/dev/null || echo ../code-generator)}

bash "${CODEGEN_PKG}"/generate-internal-groups.sh \
    deepcopy,defaulter \
    github.com/plkokanov/secretschecker/pkg/client/componentconfig \
    github.com/plkokanov/secretschecker/pkg/apis \
    github.com/plkokanov/secretschecker/pkg/apis \
    "config:v1alpha1" \
    -h "${SCRIPT_ROOT}/hacks/LICENSE_BOILERPLATE.txt"

bash "${CODEGEN_PKG}"/generate-internal-groups.sh \
    conversion \
    github.com/plkokanov/secretschecker/pkg/client/componentconfig \
    github.com/plkokanov/secretschecker/pkg/apis \
    github.com/plkokanov/secretschecker/pkg/apis \
    "config:v1alpha1" \
    --extra-peer-dirs=github.com/plkokanov/secretschecker/pkg/apis/config,github.com/plkokanov/secretschecker/pkg/apis/config/v1alpha1,k8s.io/apimachinery/pkg/apis/meta/v1,k8s.io/apimachinery/pkg/conversion,k8s.io/apimachinery/pkg/runtime,k8s.io/component-base/config,k8s.io/component-base/config/v1alpha1 \
    -h "${SCRIPT_ROOT}/hacks/LICENSE_BOILERPLATE.txt"

# To use your own boilerplate text append:
#   --go-header-file "${SCRIPT_ROOT}"/hack/custom-boilerplate.go.txt