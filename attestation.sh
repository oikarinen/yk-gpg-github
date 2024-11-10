#!/bin/bash

# Copyright (c) 2024 @oikarinen

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

# Export the attestation certificate and the signer certificate from the YubiKey
# See https://developers.yubico.com/PGP/Attestation.html for more information


function target_path() {
    local user=$1
    if [ -z "$user" ]; then
        echo "User not specified" >&2
        exit 1
    fi
    echo "yubikeys/${user}-attestation/"
}

function export_attestation() {
    target_path=$1
    mkdir -p "$target_path"
    for type in AUT DEC SIG; do
        ykman openpgp keys attest --format PEM "$type" "${target_path}/attestation-${type}.pem"
    done
    ykman openpgp certificates export --format PEM ATT "${target_path}/intermediate.pem"
}

# https://www.yubico.com/support/security-advisories/ysa-2024-03/
function check_vulnerable() {
    local json=$1
    echo "$json" | jq '.Attestation.Version | .Major >= 5 and .Minor >= 7' | grep -q true || {
        echo "YubiKey is vulnerable to YSA-2024-03" >&2
        #TODO exit 1
    }
}

function verify_attestation() {
    target_path=$1
    type=$2
    ca_path="yubikeys/opgp-attestation-ca.pem"

    if [ ! -f "${target_path}/attestation-${type}.pem" ]; then
        echo "Attestation certificate not found" >&2
        exit 1
    fi
    if [ ! -f "${target_path}/intermediate.pem" ]; then
        echo "Intermediate certificate not found" >&2
        exit 1
    fi
    if [ ! -f "$ca_path" ]; then
        echo "CA certificate not found" >&2
        exit 1
    fi
    if [ "$type" != "AUT" ] && [ "$type" != "DEC" ] && [ "$type" != "SIG" ]; then
        echo "Invalid attestation type" >&2
        exit 1
    fi

    local result
    result=$(yk-attest-verify pgp \
        "${target_path}/attestation-${type}.pem" \
        "${target_path}/intermediate.pem" \
        --allowed-slots="$type" \
        --allowed-keysources="generated" \
        --json)
    check_vulnerable "$result"
    echo -n "Serial: "
    echo "$result" | jq -r '.Attestation.Serial'
    fingerprint=$(echo "$result" | jq -r '.Attestation.Fingerprint')
}

case "$1" in
    export)
        # Developer mode, extract user from env or git config
        user=${GITHUB_USERNAME:-$(git config --get user.name)}
        if [ -z "$user" ]; then
            echo "Please set GITHUB_USERNAME or git config user.name" >&2
            exit 1
        fi
        attestation_path=$(target_path "$user")
        export_attestation "$attestation_path"
        ;;
    verify)
        if [ -z "$2" ]; then
            echo "Attestation type not specified" >&2
            exit 1
        fi
        if [ -z "$3" ]; then
            echo "User not specified" >&2
            exit 1
        fi
        # CI mode, type and user is passed as an argument
        attestation_path=$(target_path "$3")
        verify_attestation "$attestation_path" "$2"
        ;;
    *)
        echo "Usage: $0 <export|verify USER>" >&2
        exit 1
        ;;
esac
