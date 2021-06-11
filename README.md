# Garden-Login

[![reuse compliant](https://reuse.software/badge/reuse-compliant.svg)](https://reuse.software/)

`garden-login`s `get-client-certificate` command can be used as a `kubectl` [credential plugin](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#client-go-credential-plugins). It fetches the `cluster-admin` credentials from the API introduced with [GEP-16](https://github.com/gardener/gardener/blob/master/docs/proposals/16-adminkubeconfig-subresource.md). See more details under [Authentication Flow](#authentication-flow)

With GEP-16, users are able to generate kubeconfigs for `Shoot` clusters with short-lived certificates, to access the cluster as `cluster-admin`.


## Configure garden-login
`garden-login` requires a configuration file. The default location is in `~/.garden/garden-login.yaml`.
### Config path overwrite:
- The `garden-login` config path can be overwritten with the environment variable `GL_HOME`.
- The `garden-login` config name can be overwritten with the environment variable `GL_CONFIG_NAME`.

```bash
export GL_HOME=/alternate/garden/config/dir
export GL_CONFIG_NAME=myconfig # without extension!
# config is expected to be under /alternate/garden/config/dir/myconfig.yaml
```

### Example config:
```yaml
gardenClusters:
- clusterIdentity: landscape-dev # Unique identifier of the garden cluster. See cluster-identity ConfigMap in kube-system namespace of the garden cluster
  kubeconfig: ~/path/to/garden-cluster/kubeconfig.yaml
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
     apiVersion: client.authentication.k8s.io/v1beta1
     provideClusterInfo: true
     command: kubectl
     args:
       - garden-login
       - get-client-certificate
```

An example `kubeconfig` supporting `kubectl` version `v1.11.0` onwards can be found under [example/02-kubeconfig.yaml](example/02-kubeconfig.yaml).

## Authentication Flow
The following describes the flow to authenticate against a `Shoot` cluster as cluster admin:

1. The user would either download the `Shoot` cluster `kubeconfig`
    - using the `gardener/dashboard` (TODO)
    - by targeting the cluster with `gardenctl` (TODO)
    - or using the API to fetch the secret (TODO)
2. `kubectl` is then configured to use the downloaded `kubeconfig` for the shoot cluster
3. A `kubectl` command is executed, e.g. `kubectl get namespaces`
4. The `garden-login` credential plugin is called to print the `ExecCredential` to `stdout`, see [input and output formats](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#input-and-output-formats) for more information.
5. In case a valid credential is already cached locally it is returned directly. Otherwise, a new credential has to be requested
6. According to the garden cluster identity under `clusters[].cluster.extensions[].extension.gardenClusterIdentity`, the `garden-login` plugin searches a matching garden cluster in its configuration file (`gardenClusters[].clusterIdentity`) to get the `kubeconfig` of the garden cluster
7. The `garden-login` plugin calls `shoots/adminkubeconfig` resource with an `AdminKubeConfigRequest` for the `Shoot` cluster referenced under `clusters[].cluster.extensions[].extension.shootRef`
8. The `garden-login` plugin takes the x509 client certificate from the returned `AdminKubeConfigRequest` under `status.kubeconfig` and prints it as `ExecCredential` to `stdout`
