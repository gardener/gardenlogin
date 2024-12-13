# Gardenlogin
[![REUSE status](https://api.reuse.software/badge/github.com/gardener/gardenlogin)](https://api.reuse.software/info/github.com/gardener/gardenlogin)
[![Slack channel #gardener](https://img.shields.io/badge/slack-gardener-brightgreen.svg?logo=slack)](https://kubernetes.slack.com/messages/gardener)
[![Go Report Card](https://goreportcard.com/badge/github.com/gardener/gardenlogin)](https://goreportcard.com/report/github.com/gardener/gardenlogin)
[![release](https://badge.fury.io/gh/gardener%2Fgardenlogin.svg)](https://badge.fury.io/gh/gardener%2Fgardenlogin)

The `gardenlogin`s `get-client-certificate` command can be used as a `kubectl` [credential plugin](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#client-go-credential-plugins). It supports fetching credentials from two subresources: [`shoots/adminkubeconfig`](https://github.com/gardener/gardener/blob/master/docs/proposals/16-adminkubeconfig-subresource.md) and `shoots/viewerkubeconfig`

By default, the plugin retrieves credentials from the `shoots/adminkubeconfig` subresource, granting full administrative access. Alternatively, it can fetch credentials from the `shoots/viewerkubeconfig` subresource for read-only access.

The level of access for the fetched credentials can be controlled using the `--access-level` flag. This flag supports three options: `auto`, `admin`, and `viewer`. The default option is `auto`, which first attempts to fetch admin-level credentials and falls back to viewer-level credentials if the former is unsuccessful.

For more information on how the plugin operates, refer to the [Authentication Flow](#authentication-flow) section.

## Installation

Install the latest release from [Homebrew](https://brew.sh/), [Chocolatey](https://chocolatey.org/packages/gardenlogin) or [GitHub Releases](https://github.com/gardener/gardenlogin/releases).

### Install using Package Managers

```sh
# Homebrew (macOS and Linux)
brew install gardener/tap/gardenlogin

# Chocolatey (Windows)
choco install gardenlogin
```
### Install using Nix

Nix with [Flakes](https://nixos.wiki/wiki/Flakes) (prerequisite: [Nix](https://nixos.org/download), the package manager):

```bash
# Nix (macOS, Linux, and Windows)

# development version
nix profile install github:gardener/gardenlogin
# or release <version>
nix profile install github:gardener/gardenlogin/<version>

#check installation
nix profile list | grep gardenlogin

# optionally, open a new shell and verify that cmd completion works
gardenlogin --help
kubectl gardenlogin --help
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
curl -LO "https://github.com/gardener/gardenlogin/releases/download/${version}/gardenlogin_${os}_${arch}"

# Make the gardenlogin binary executable
chmod +x "./gardenlogin_${os}_${arch}"

# Move the binary in to your PATH
sudo mv "./gardenlogin_${os}_${arch}" /usr/local/bin/gardenlogin

# create kubectl-gardenlogin symlink
sudo ln -s /usr/local/bin/gardenlogin /usr/local/bin/kubectl-gardenlogin
```

## Configure Gardenlogin
`gardenlogin` requires a configuration file. The default location is in `~/.garden/gardenlogin.yaml`. 

If no configuration file is found, it falls back to the `gardenctl-v2` configuration file (`~/.garden/gardenctl-v2.yaml`) which shares the same configuration properties.

**Hint:** If you intend to use both `gardenlogin` and [gardenctl-v2](https://github.com/gardener/gardenctl-v2/), it is recommended to store the configuration file in `~/.garden/gardenctl-v2.yaml`. This allows both applications to share a single configuration.

### Example Config
```yaml
gardens:
- identity: landscape-dev # Unique identity of the garden cluster. See cluster-identity ConfigMap in kube-system namespace of the garden cluster
  kubeconfig: ~/path/to/garden-cluster/kubeconfig.yaml
#  context: different-context # Overrides the current-context of the garden cluster kubeconfig  
```

### Config Path Overwrite
- The `gardenlogin` config path can be overwritten with the environment variable `GL_HOME`.
- The `gardenlogin` config name can be overwritten with the environment variable `GL_CONFIG_NAME`.

```bash
export GL_HOME=/alternate/garden/config/dir
export GL_CONFIG_NAME=myconfig # without extension!
# config is expected to be under /alternate/garden/config/dir/myconfig.yaml
```

## Usage
An example `kubeconfig` for a shoot cluster looks like the following:

```yaml
# supported with kubectl version v1.20.0 onwards
apiVersion: v1
kind: Config
clusters:
- name: shoot--myproject--mycluster
  cluster:
    server: https://api.mycluster.myproject.example.com
    certificate-authority-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCi4uLgotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0t
    extensions:
    - name: client.authentication.k8s.io/exec
      extension:
        shootRef:
          namespace: garden-myproject
          name: mycluster
        gardenClusterIdentity: landscape-dev # must match with the garden cluster identity from the config
contexts:
- name: shoot--myproject--mycluster
  context:
    cluster: shoot--myproject--mycluster
    user: shoot--myproject--mycluster
current-context: shoot--myproject--mycluster
users:
- name: shoot--myproject--mycluster
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1
      provideClusterInfo: true
      command: kubectl
      args:
      - gardenlogin
      - get-client-certificate
```

An example `kubeconfig` supporting `kubectl` version `v1.11.0` onwards can be found under [example/01-kubeconfig-legacy.yaml](example/01-kubeconfig-legacy.yaml).

## Authentication Flow
The following describes the flow to authenticate against a `Shoot` cluster as cluster admin:

1. The user would either download the `Shoot` cluster `kubeconfig`
    - using the `gardener/dashboard` (refer to [connect-kubectl.md#download-from-dashboard](https://github.com/gardener/dashboard/blob/master/docs/usage/connect-kubectl.md#download-from-dashboard))
    - by targeting the cluster with `gardenctl` (refer to [connect-kubectl.md#copy-and-run-gardenctl-target-command](https://github.com/gardener/dashboard/blob/master/docs/usage/connect-kubectl.md#copy-and-run-gardenctl-target-command))
    - or using `gardenctl kubeconfig --raw --garden landscape-dev --project my-project --shoot my-shoot` to print the kubeconfig for the respective target cluster
2. `kubectl` is then configured to use the downloaded `kubeconfig` for the shoot cluster
3. A `kubectl` command is executed, e.g. `kubectl get namespaces`
4. The `gardenlogin` credential plugin is called to print the `ExecCredential` to `stdout`, see [input and output formats](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#input-and-output-formats) for more information.
5. In case a valid credential is already cached locally it is returned directly. Otherwise, a new credential has to be requested
6. According to the garden cluster identity under `clusters[].cluster.extensions[].extension.gardenClusterIdentity`, the `gardenlogin` plugin searches a matching garden cluster in its configuration file (`gardenClusters[].clusterIdentity`) to get the `kubeconfig` of the garden cluster
7. The `gardenlogin` plugin calls `shoots/adminkubeconfig` resource with an `AdminKubeConfigRequest` for the `Shoot` cluster referenced under `clusters[].cluster.extensions[].extension.shootRef`
8. The `gardenlogin` plugin takes the x509 client certificate from the returned `AdminKubeConfigRequest` under `status.kubeconfig` and prints it as `ExecCredential` to `stdout`
