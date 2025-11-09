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

# Generate new GPG key on a Yubikey for signing commits and add it to GitHub.
# The private key never leaves the Yubikey.

# This script serves as a reminder of how poor the GnuPG tooling is, so that one
# day someone will write a better tool for this purpose. Some pointers:
# * Skip gpg altogether: https://developers.yubico.com/SSH/Securing_git_with_SSH_and_FIDO2.html
# * https://github.com/phiekl/yk-init
# * https://github.com/FiloSottile/yubikey-agent

# TODO Trap to cleanup all temp files
# TODO Validate signing git commits
# TODO Catch the revocation certificate and store it somewhere safe i.e. gpg --gen-revoke
# TODO Configure pinentry i.e.  echo "pinentry-program $(which pinentry-mac)" >> "${HOME}/.gnupg/gpg-agent.conf"
# TODO Proper parsing of the arguments
# TODO Add support for selecting the key by serial number

set -eo pipefail

# Parse the arguments
ARGS_FORCE="false"
while [[ "$#" -gt 0 ]]; do
    case $1 in
    -f | --force)
        # Reset the card and skip all confirmations and verifications that would ask for a pin.
        # New pins for the card are still asked.
        ARGS_FORCE="true"
        ;;
    *)
        echo "Unknown parameter passed: $1"
        exit 1
        ;;
    esac
    shift
done

# This needs to be after parsing the arguments
set -u

# The default admin and user pins for any Yubikey
DEFAULT_ADMINPIN="12345678"
DEFAULT_USERPIN="123456"

function check_tools() {
    for tool in expect gh git gpg ykman ; do
        if ! command -v "$tool" &> /dev/null; then
            echo "$tool is required but not found: Please install it using for example brew install, aborting!"
            exit 1
        fi
    done
}

function git_configure() {
    local fpr="$1"
    git config --global commit.gpgsign true
    git config --global user.signingkey "$fpr"
}

function github_configure() {
    local signing_keyid="$1"
    local authentication_keyid="$2"
    local email="$3"
    local name="$4"
    local comment="$5"

    local gpg_public_key
    gpg_public_key="$(mktemp)"
    gpg --armor --export "$signing_keyid" > "$gpg_public_key"
    # test if file was created and not empty
    if [ ! -s "$gpg_public_key" ]; then
        echo "Failed to export the public key with keyid ${signing_keyid}, aborting!"
        exit 1
    fi
    local ssh_public_key
    ssh_public_key="$(mktemp)"
    gpg --export-ssh-key "$authentication_keyid" > "$ssh_public_key"
    if [ ! -s "$ssh_public_key" ]; then
        echo "Failed to export the ssh key with keyid ${authentication_keyid}, aborting!"
        exit 1
    fi

    gh auth logout || true

    echo "Please login to GitHub to authorize adding the key"
    gh auth login --scopes write:gpg_key --scopes admin:public_key

    gh gpg-key add "$gpg_public_key" -t "GPG key for $name <$email> $comment"
    rm -f "$gpg_public_key"
    gh ssh-key add "$ssh_public_key" -t "GPG key for $name <$email> $comment" --type "authentication"
    rm -f "$ssh_public_key"

    gh auth logout
}

function github_test_ssh() {
    ssh git@github.com
}

function gpg_agent_configure() {
    echo "enable-ssh-support:0:1" | gpgconf --change-options gpg-agent
    echo "no-allow-loopback-pinentry:16:" | gpgconf --change-options gpg-agent # 16: remove if set
    # TODO pinentry-program /opt/homebrew/bin/pinentry-mac
    gpg-connect-agent "reloadagent" /bye
}

function gpg_card_change_pins() {
    local pin="$1"
    local adminpin="$2"
    # TODO poor security, these are present in the ps output
    ykman openpgp access change-pin -P "$DEFAULT_USERPIN" -n "$pin"
    ykman openpgp access change-admin-pin -a "$DEFAULT_ADMINPIN" -n "$adminpin"
}

function gpg_card_configure() {
    local email="$1"
    local name="$2"
    gpg-connect-agent \
        "OPTION pinentry-mode=loopback" \
        "/let pin $DEFAULT_ADMINPIN" \
        "/definq PASSPHRASE pin" \
        "SCD SETATTR LOGIN-DATA $email" \
        "SCD SETATTR DISP-NAME $name" \
        "SCD SETATTR DISP-LANG en" \
        "SCD SETATTR KEY-ATTR --force 1 1 rsa4096" \
        "SCD SETATTR KEY-ATTR --force 2 1 rsa4096" \
        "SCD SETATTR KEY-ATTR --force 3 1 rsa4096" \
        /bye

    expect - << EOF
    spawn gpg --card-edit --pinentry-mode loopback
    set prompt "gpg/card>"
    expect \$prompt
    send -- "admin\r"
    expect "Admin commands are allowed" {
        send -- "kdf-setup\r"
        expect "Enter passphrase:" {
            stty -echo
            send -- "$DEFAULT_ADMINPIN\r"
            stty echo
        }
        expect \$prompt {
            send -- "q\r"
            expect eof
        }
    }
EOF

    ykman openpgp access set-signature-policy -a "$DEFAULT_ADMINPIN" once
}

function gpg_card_generate_key() {
    local pin="$1"
    local adminpin="$2"
    local email="$3"
    local name="$4"
    local comment="$5"

    # if only gpg-card generate supported reading the pin from stdin
    expect - << EOF
    spawn gpg --card-edit --pinentry-mode loopback
    set prompt "gpg/card>"
    expect \$prompt
    send -- "admin\r"
    expect "Admin commands are allowed" {
        send -- "generate\r"
        expect "Make off-card backup of encryption key? (Y/n)" {
            send -- "n\r"
        }
        expect "Enter passphrase:" {
            stty -echo
            send -- "$pin\r"
            stty echo
        }
        expect "Key is valid for?" {
            send -- "0\r"
        }
        expect "Is this correct? (y/N)" {
            send -- "y\r"
        }
        expect "Real name:" {
            send -- "$name\r"
        }
        expect "Email address:" {
            send -- "$email\r"
        }
        expect "Comment:" {
            send -- "$comment\r"
        }
        expect "Change (N)ame, (C)omment, (E)mail or (O)kay/(Q)uit?" {
            send -- "o\r"
        }
        expect "Enter passphrase:" {
            stty -echo
            send -- "$adminpin\r"
            stty echo
            puts "\rNow generating the key, this will take a while..."
            set timeout -1
            puts "\rDone generating the key"

        }
        expect "public and secret key created and signed." {
            set timeout 60
            send -- "q\r"
            expect eof
        }
    }
EOF
}
# gpg: revocation certificate stored as '/Users/tapio/.gnupg/openpgp-revocs.d/<redacted>.rev'

function gpg_test_key() {
    local keyid="$1"
    echo "hello world" | \
        gpg --encrypt --sign --armor --local-user "$keyid" --recipient "$keyid" | \
        gpg --decrypt --armor
}

function gpg_extract_fingerprint() {
    local type="$1"
    # Ugly hack to get the fingerprint.
    gpg-card list | \
        grep -iE "^${type} key" -A8 | \
        grep -E "^[ ]+fpr" | \
        awk '{print $3}'
}

function is_valid_fingerprint() {
    local fpr="$1"
    if [[ -z "$fpr" ]]; then
        echo "Failed to get the fingerprint, aborting!"
        exit 1
    elif [[ "$(echo "$fpr" | wc -l)" -gt 1 ]]; then
        echo "Multiple keys found, aborting!"
        exit 1
    fi
}

function is_valid_serial() {
    local serial="$1"
    if [[ -z "$serial" ]]; then
        echo "No Yubikey found, please insert one and try again."
        exit 1
    elif [[ "$(echo "$serial" | wc -l)" -gt 1 ]]; then
        echo "Multiple Yubikeys found, please remove all but one and try again."
        exit 1
    fi
}

function is_valid_email() {
    local email="$1"
    if [[ -z "$email" ]]; then
        echo "No email address found in git config, please set it and try again."
        exit 1
    fi
    if [[ ! "$email" =~ "@" ]]; then
        echo "Invalid email address found in git config, please set it and try again."
        exit 1
    fi
}

function main() {
    # Get the Yubikey serial number
    serial="$(ykman list --serials)"
    is_valid_serial "$serial"

    # Reset the Yubikey if --force is set
    if [[ "$ARGS_FORCE" == "true" ]]; then
        ykman openpgp reset
    fi

    # Pull user details from git config
    local comment="on yubikey $serial"
    local email
    email="$(git config --get user.email)"
    is_valid_email "$email"
    local name
    name="$(git config --get user.name)"

    # Skip the confirmation if --force is set
    if [[ "$ARGS_FORCE" != "true" ]]; then
        read -r -p "Generate key for $name <$email>? (Ctrl+C to abort)"
    fi

    # Configure gpg-agent
    gpg_agent_configure

    # Configure Yubikey

    gpg_card_configure "$email" "$name"

    # Change the pins
    echo "Please change the pins now:"
    local pin
    read -s -r -p "Enter the new USER pin: " pin
    echo ""
    local adminpin
    read -s -r -p "Enter the new ADMIN pin: " adminpin
    echo ""
    gpg_card_change_pins "$pin" "$adminpin"

    # Generate the key
    gpg_card_generate_key "$pin" "$adminpin" "$email" "$name" "$comment"

    # Get the signin key fingerprint
    signing_fpr=$(gpg_extract_fingerprint "Signature")
    is_valid_fingerprint "$signing_fpr"
    authentication_fpr=$(gpg_extract_fingerprint "Authentication")
    is_valid_fingerprint "$authentication_fpr"

    # Skip the confirmation if --force is set
    if [[ "$ARGS_FORCE" != "true" ]]; then
        read -r -p "Hit enter to continue with verifying the key"
        # Test the key
        gpg_test_key "$signing_fpr"
    fi

    # Export the public and ssh keys and add them to GitHub
    local _yesno
    if [[ "$ARGS_FORCE" == "true" ]]; then
        # Skip the confirmation if --force is set
        _yesno="y"
    else
        read -r -p "Add the gpg and ssh keys to GitHub? [yN]" _yesno
    fi
    if [[ "$_yesno" == "y" ]]; then
        github_configure "$signing_fpr" "$authentication_fpr" "$email" "$name" "$comment"

        if [[ "$ARGS_FORCE" != "true" ]]; then
            # Test connection to GitHub
            github_test_ssh
        fi
    fi

    # Configure git to use the key
    if [[ "$ARGS_FORCE" == "true" ]]; then
        # Skip the confirmation if --force is set
        _yesno="y"
    else
        read -r -p "Use the above key for signing git commits? (Ctrl+C to abort)" _yesno
    fi
    if [[ "$_yesno" == "y" ]]; then
        git_configure "$signing_fpr"
    fi

    echo "All done!"

    exit 0
}

# Check for required tools
check_tools

# Run the main loop
main
