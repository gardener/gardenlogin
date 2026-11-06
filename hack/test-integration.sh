#!/usr/bin/env bash

# SPDX-FileCopyrightText: Contributors to the Gardener project
#
# SPDX-License-Identifier: Apache-2.0

set -o errexit
set -o pipefail

if [ -z "$SOURCE_PATH" ]; then
  SOURCE_PATH="$(dirname "$0")/.."
fi
export SOURCE_PATH="$(readlink -f "$SOURCE_PATH")"

GO_TEST_TIMEOUT="${GO_TEST_TIMEOUT:-5m}"
GO_TEST_RACE="${GO_TEST_RACE:-0}"
GO_TEST_LD_FLAGS="${GO_TEST_LD_FLAGS:-$("${SOURCE_PATH}/hack/get-build-ld-flags.sh")}"

if [[ "${insecureAllowArgumentOnly:-false}" == "true" ]]; then
  GINKGO_LABEL_FILTER="${GINKGO_LABEL_FILTER:-!argument-only-disabled}"
else
  GINKGO_LABEL_FILTER="${GINKGO_LABEL_FILTER:-!argument-only-enabled}"
fi

OS=${OS:-$(go env GOOS)}
ARCH=${ARCH:-$(go env GOARCH)}

function run_test {
  local component=$1
  local target_dir=$2
  echo "> Test $component"

  pushd "$target_dir"

  RACE_FLAG=""
  if [ "${GO_TEST_RACE}" = "1" ]; then
    RACE_FLAG="-race"
  fi

  local -a ld_flags=()
  if [[ -n "${GO_TEST_LD_FLAGS}" ]]; then
    ld_flags=(-ldflags "${GO_TEST_LD_FLAGS}")
  fi

  GO111MODULE=on go test "${ld_flags[@]}" ${RACE_FLAG} -timeout "${GO_TEST_TIMEOUT}" -coverprofile cover.out ./... -ginkgo.label-filter="${GINKGO_LABEL_FILTER}"

  popd
}

run_test gardenlogin "${SOURCE_PATH}"
