# Requirements
Node.js version 22 or higher

Git config should have email address set

Git config should have user name set

```
~/.gnupg              # folder needs to exist
chmod 700 ~/.gnupg    # folder should have following access rights
```

# yk-gpg-github

Generate new GPG key on a Yubikey for signing commits and add it to GitHub. The private key never leaves the device.

This script serves as a reminder of how poor the GnuPG tooling is, so that one
day someone will write a better tool for this purpose. Some pointers:

* Skip GnuPG altogether: https://developers.yubico.com/SSH/Securing_git_with_SSH_and_FIDO2.html
* https://github.com/phiekl/yk-init
* https://github.com/FiloSottile/yubikey-agent

# Usage
First set your git user email and name like
```sh
git config --global user.email "first.last@domain.com"
git config --global user.name "First Last"
```

Then run:
`./main.sh [--force]`
