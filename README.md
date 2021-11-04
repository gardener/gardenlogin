## Installation

Install the latest release from [Homebrew](https://brew.sh/), [Chocolatey](https://chocolatey.org/packages/gardenlogin) or [GitHub Releases](https://github.com/gardener/gardenlogin/releases).

### Install using Package Managers

```sh
# Homebrew (macOS and Linux)
brew install gardener/tap/gardenlogin

# Chocolatey (Windows)
choco install gardenlogin
```

### Install from Github Release

If you install via GitHub releases, you need to put the `gardenlogin` binary on your path under the name `kubectl-gardenlogin` so that the [kubectl plugin mechanism](https://kubernetes.io/docs/tasks/extend-kubectl/kubectl-plugins/) can find it when you invoke `kubectl gardenlogin`. The other install methods do this for you.

```bash
# Example for macOS

# set operating system and architecture
os=darwin # choose between darwin, linux, windows
arch=amd64

# Get latest version. Alternatively set your desired version
version=$(curl -s https://raw.githubusercontent.com/gardener/gardenlogin/master/LATEST)

# Download gardenlogin
curl -LO https://github.com/gardener/gardenlogin/releases/download/$(curl -s https://raw.githubusercontent.com/gardener/gardenlogin/master/LATEST)/"gardenlogin_${os}_${arch}"

# Make the gardenlogin binary executable
chmod +x "./gardenlogin_${os}_${arch}"

# Move the binary in to your PATH
sudo mv "./gardenlogin_${os}_${arch}" /usr/local/bin/gardenlogin

# create kubectl-gardenlogin symlink
ln -s /usr/local/bin/gardenlogin /usr/local/bin/kubectl-gardenlogin
```
