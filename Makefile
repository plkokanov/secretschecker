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

VERSION=0.0.0
VCS="github.com"
ORGANIZATION="plkokanov"
PROJECT="secretschecker"
REPOSITORY=${VCS}/${ORGANIZATION}/${PROJECT}

.PHONY: build
build:
	@GO111MODULE=on go build \
    -v \
    -mod vendor \
    -o "bin/secretschecker" \
    -ldflags "-w -X ${REPOSITORY}/pkg/version.Version=${VERSION}" \
    cmd/main.go

.PHONY: start
start:
	@GO111MODULE=on go run -mod=vendor cmd/main.go --config ./example/config.yaml

.PHONY: revendor
revendor:
	@GO111MODULE=on go mod vendor
	@GO111MODULE=on go mod tidy

.PHONY: generate
generate:
	@./hacks/update-codegen.sh