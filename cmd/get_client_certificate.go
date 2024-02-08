/*
SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors

SPDX-License-Identifier: Apache-2.0
*/

package cmd

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	authenticationv1alpha1 "github.com/gardener/gardener/pkg/apis/authentication/v1alpha1"
	gardenscheme "github.com/gardener/gardener/pkg/client/core/clientset/versioned/scheme"
	"github.com/mitchellh/go-homedir"
	"github.com/spf13/cobra"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/kubernetes/scheme"
	clientauthenticationv1 "k8s.io/client-go/pkg/apis/clientauthentication/v1"
	clientauthenticationv1beta1 "k8s.io/client-go/pkg/apis/clientauthentication/v1beta1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/auth/exec"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/clientcmd/api"
	"k8s.io/klog/v2"
	"k8s.io/utils/pointer"
	"k8s.io/utils/strings/slices"

	"github.com/gardener/gardenlogin/internal/certificatecache"
	"github.com/gardener/gardenlogin/internal/certificatecache/store"
	"github.com/gardener/gardenlogin/internal/cmd/util"
)

const (
	execInfoEnv = "KUBERNETES_EXEC_INFO"

	accessLevelAuto   = "auto"
	accessLevelAdmin  = "admin"
	accessLevelViewer = "viewer"
)

var (
	ioStreams = util.IOStreams{
		In:     os.Stdin,
		Out:    os.Stdout,
		ErrOut: os.Stderr,
	}
	// getClientCertificateCmd represents the getClientCertificate command.
	getClientCertificateCmd *cobra.Command
)

type kubeconfigRequestStatus struct {
	kubeconfig          []byte
	expirationTimestamp metav1.Time
}

// ExecPluginConfig contains additional data which is needed for the
// gardenlogin plugin to authenticate against the shoot cluster.
type ExecPluginConfig struct {
	// ShootRef references the shoot cluster
	ShootRef ShootRef `json:"shootRef"`
	// GardenClusterIdentity is the cluster identity of the garden cluster.
	// See cluster-identity ConfigMap in kube-system namespace of the garden cluster
	GardenClusterIdentity string `json:"gardenClusterIdentity"`
}

// ShootRef references the shoot cluster by namespace and name.
type ShootRef struct {
	// Namespace is the namespace of the shoot cluster
	Namespace string `json:"namespace"`
	// Namespace is the name of the shoot cluster
	Name string `json:"name"`
}

// GetClientCertificateOptions has the data required to perform the getClientCertificate operation.
type GetClientCertificateOptions struct {
	// IOStreams provides the standard names for iostreams
	IOStreams util.IOStreams
	// CertificateCacheStore is the store for accessing the certificatecache.CertificateSet items
	CertificateCacheStore store.Interface

	// Clock provides the current time
	Clock util.Clock

	// GroupVersion determines the version for the output ExecCredential
	GroupVersion schema.GroupVersion

	// Common user flags

	// ShootCluster holds the data of the shoot kubernetes cluster.
	// This field is not set for kubectl versions older than v1.20.0 and starting with v1.11.0 as the KUBERNETES_EXEC_INFO environment variable is not set
	// If not nil, the Server and CertificateAuthorityData must match with what is returned in the kubeconfig of the "shoots/adminkubeconfig" subresource.
	// If nil the cluster of the current context from the kubeconfig returned by the "shoots/adminkubeconfig" subresource is used.
	// TODO once we drop support for kubectl versions older than v1.20.0, this field should be made required
	// +optional
	ShootCluster *clientauthenticationv1.Cluster
	// ShootRef references the shoot cluster for which the client certificate credentials should be obtained
	ShootRef ShootRef

	// GardenClusterIdentity is the cluster identity of the garden cluster.
	// See cluster-identity ConfigMap in kube-system namespace of the garden cluster
	GardenClusterIdentity string

	// REST Client for the garden cluster
	GardenCoreV1Beta1RESTClient rest.Interface

	// CertificateCacheDir is the directory of the certificate cache
	CertificateCacheDir string

	// KubeconfigExpirationSeconds defines the validity duration of the requested credential
	KubeconfigExpirationSeconds int64

	// AccessLevel specifies the user access level for the requested credential
	AccessLevel string
}

func init() {
	ctx := context.Background()
	logger := klog.FromContext(ctx)

	dir, err := homedir.Dir()
	if err != nil {
		logger.Error(err, "could not determine home directory")
	}

	f := util.NewFactory(dir)

	getClientCertificateCmd = NewCmdGetClientCertificate(f, ioStreams)

	rootCmd.AddCommand(getClientCertificateCmd)
}

// NewGetClientCertificateOptions returns the options to perform the get-client-certificate command.
func NewGetClientCertificateOptions(ioStreams util.IOStreams) *GetClientCertificateOptions {
	return &GetClientCertificateOptions{
		IOStreams: ioStreams,
	}
}

const (
	flagGardenClusterIdentity = "garden-cluster-identity"
	flagName                  = "name"
	flagNamespace             = "namespace"
	flagCertificateCacheDir   = "certificate-cache-dir"
	flagExpirationSeconds     = "expiration-seconds"
	flagAccessLevel           = "access-level"
)

// NewCmdGetClientCertificate returns the get-client-certificate cobra.Command.
func NewCmdGetClientCertificate(f util.Factory, ioStreams util.IOStreams) *cobra.Command {
	o := NewGetClientCertificateOptions(ioStreams)
	cmd := &cobra.Command{
		Use:   "get-client-certificate",
		Short: "Returns the client-certificate. To be used as kubectl credential plugin. KUBERNETES_EXEC_INFO env var has to be set",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := o.Complete(f, cmd, args); err != nil {
				return fmt.Errorf("failed to complete command options: %w", err)
			}
			if err := o.Validate(); err != nil {
				return err
			}

			ctx := context.Background()
			return o.RunGetClientCertificate(ctx)
		},
	}

	cmd.Flags().StringVar(&o.ShootRef.Name, flagName, "", "Name of the shoot cluster")
	cmd.Flags().StringVar(&o.ShootRef.Namespace, flagNamespace, "", "Namespace of the shoot cluster")
	cmd.Flags().StringVar(&o.GardenClusterIdentity, flagGardenClusterIdentity, "", "Cluster identity of the garden cluster")
	cmd.Flags().StringVar(&o.CertificateCacheDir, flagCertificateCacheDir, filepath.Join(f.HomeDir(), ".kube", "cache", "gardenlogin"), "Directory of the certificate cache")
	cmd.Flags().Int64Var(&o.KubeconfigExpirationSeconds, flagExpirationSeconds, 900, "Validity duration of the requested credential")
	cmd.Flags().StringVar(&o.AccessLevel, flagAccessLevel, accessLevelAuto, `Defines the access level of the credential returned by the plugin. Can be "auto", "admin", or "viewer".
	"auto" - Attempts to obtain admin-level credentials. If unsuccessful, it defaults to viewer-level credentials.
	"admin" - Returns a credential with cluster-admin privileges.
	"viewer" - Returns a credential with read-only access to non-encrypted API resources.`)

	utilruntime.Must(cmd.RegisterFlagCompletionFunc(flagAccessLevel, func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return o.AllowedAccessLevels(), cobra.ShellCompDirectiveNoFileComp
	}))

	return cmd
}

// Complete adapts from the command line args to the data required.
func (o *GetClientCertificateOptions) Complete(f util.Factory, _ *cobra.Command, _ []string) error {
	env := os.Getenv(execInfoEnv)
	if env != "" { // KUBERNETES_EXEC_INFO env variable set for kubectl versions starting with v1.20.0
		obj, _, err := exec.LoadExecCredential([]byte(env))
		if err != nil {
			return err
		}

		o.GroupVersion = obj.GetObjectKind().GroupVersionKind().GroupVersion()

		obj, err = scheme.Scheme.ConvertToVersion(obj, clientauthenticationv1.SchemeGroupVersion)
		if err != nil {
			return fmt.Errorf("cannot convert to %s: %w", clientauthenticationv1.SchemeGroupVersion, err)
		}

		v1ExecCredential, ok := obj.(*clientauthenticationv1.ExecCredential)
		if !ok {
			return errors.New("obj is not of type clientauthenticationv1.ExecCredential")
		}

		var extension ExecPluginConfig

		if v1ExecCredential.Spec.Cluster.Config.Raw != nil {
			if err := json.Unmarshal(v1ExecCredential.Spec.Cluster.Config.Raw, &extension); err != nil {
				return err
			}
		}

		o.ShootCluster = v1ExecCredential.Spec.Cluster

		if o.GardenClusterIdentity == "" {
			o.GardenClusterIdentity = extension.GardenClusterIdentity
		}

		if o.ShootRef.Name == "" {
			o.ShootRef.Name = extension.ShootRef.Name
		}

		if o.ShootRef.Namespace == "" {
			o.ShootRef.Namespace = extension.ShootRef.Namespace
		}
	} else {
		// fallback to v1beta1 for kubectl versions < v1.20.0
		o.GroupVersion = clientauthenticationv1beta1.SchemeGroupVersion
	}

	o.CertificateCacheStore = f.CertificateStore(o.CertificateCacheDir)

	var err error

	if o.GardenClusterIdentity != "" {
		o.GardenCoreV1Beta1RESTClient, err = f.RESTClient(o.GardenClusterIdentity)
		if err != nil {
			return err
		}
	}

	if o.AccessLevel == "" {
		o.AccessLevel = accessLevelAuto
	}

	o.Clock = f.Clock()

	return nil
}

// Validate makes sure provided values for GetClientCertificateOptions are valid.
func (o *GetClientCertificateOptions) Validate() error {
	if os.Getenv(execInfoEnv) != "" {
		if o.ShootCluster == nil {
			return errors.New("cluster must be specified")
		}

		if len(o.ShootCluster.Server) == 0 {
			return errors.New("server must be specified")
		}
	}

	if len(o.ShootRef.Name) == 0 {
		return errors.New("name must be specified. Hint: update kubectl in case you are using a version older than v1.20.0")
	}

	if len(o.ShootRef.Namespace) == 0 {
		return errors.New("namespace must be specified")
	}

	if len(o.GardenClusterIdentity) == 0 {
		return errors.New("garden cluster identity must be specified")
	}

	if !slices.Contains(o.AllowedAccessLevels(), o.AccessLevel) {
		return fmt.Errorf("invalid access level: %s. Access level must be one of %v", o.AccessLevel, o.AllowedAccessLevels())
	}

	return nil
}

// RunGetClientCertificate obtains the ExecCredential and writes it to the out stream.
func (o *GetClientCertificateOptions) RunGetClientCertificate(ctx context.Context) error {
	logger := klog.FromContext(ctx)

	// server is empty for kubectl versions older than v1.20.0 as the KUBERNETES_EXEC_INFO environment variable is not set
	server := ""
	if o.ShootCluster != nil {
		server = o.ShootCluster.Server
	}

	certificateCacheKey := certificatecache.Key{
		ShootServer:           server,
		ShootName:             o.ShootRef.Name,
		ShootNamespace:        o.ShootRef.Namespace,
		GardenClusterIdentity: o.GardenClusterIdentity,
		AccessLevel:           o.AccessLevel,
	}

	cachedCertificateSet, err := o.CertificateCacheStore.FindByKey(certificateCacheKey)
	if err != nil {
		logger.V(4).Info("could not find a cached certificate", "error", err.Error())
	}

	v1ExecCredential, err := o.getExecCredential(ctx, certificateCacheKey, cachedCertificateSet)
	if err != nil {
		return fmt.Errorf("failed to get ExecCredential: %w", err)
	}

	execCredential, err := scheme.Scheme.ConvertToVersion(v1ExecCredential, o.GroupVersion)
	if err != nil {
		return fmt.Errorf("cannot convert to %s: %w", o.GroupVersion, err)
	}

	e := json.NewEncoder(o.IOStreams.Out)
	if err := e.Encode(execCredential); err != nil {
		return fmt.Errorf("could not write the ExecCredential: %w", err)
	}

	return nil
}

func (o *GetClientCertificateOptions) getExecCredential(ctx context.Context, certificateCacheKey certificatecache.Key, cachedCertificateSet *certificatecache.CertificateSet) (*clientauthenticationv1.ExecCredential, error) {
	logger := klog.FromContext(ctx)

	if cachedCertificateSet != nil {
		certPem, _ := pem.Decode(cachedCertificateSet.ClientCertificateData)
		if certPem == nil {
			return nil, errors.New("no PEM data found")
		}

		certificate, err := x509.ParseCertificate(certPem.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate from cache: %w", err)
		}

		now := o.Clock.Now()
		validNotBefore := now.After(certificate.NotBefore.UTC()) || now.Equal(certificate.NotBefore.UTC())
		validNotAfter := now.Before(certificate.NotAfter.UTC())

		if validNotBefore && validNotAfter {
			logger.V(4).Info("valid certificate in cache")

			return &clientauthenticationv1.ExecCredential{
				TypeMeta: metav1.TypeMeta{
					APIVersion: clientauthenticationv1.SchemeGroupVersion.String(),
					Kind:       "ExecCredential",
				},
				Status: &clientauthenticationv1.ExecCredentialStatus{
					ExpirationTimestamp:   &metav1.Time{Time: certificate.NotAfter},
					ClientCertificateData: string(cachedCertificateSet.ClientCertificateData),
					ClientKeyData:         string(cachedCertificateSet.ClientKeyData),
				},
			}, nil
		}

		logger.V(4).Info("the cached certificate is expired")
	}

	kubeconfigRequest, err := o.createKubeconfigRequest(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to request kubeconfig with access level %s: %w", o.AccessLevel, err)
	}

	userConfig, err := authInfoFromKubeconfigForCluster(kubeconfigRequest.kubeconfig, o.ShootCluster)
	if err != nil {
		return nil, fmt.Errorf("could not find matching auth info from shoot kubeconfig for given cluster: %w", err)
	}

	certificateSet := certificatecache.CertificateSet{
		ClientCertificateData: userConfig.ClientCertificateData,
		ClientKeyData:         userConfig.ClientKeyData,
	}
	if err := o.CertificateCacheStore.Save(certificateCacheKey, certificateSet); err != nil {
		return nil, err
	}

	return &clientauthenticationv1.ExecCredential{
		TypeMeta: metav1.TypeMeta{
			APIVersion: clientauthenticationv1.SchemeGroupVersion.String(),
			Kind:       "ExecCredential",
		},
		Status: &clientauthenticationv1.ExecCredentialStatus{
			ExpirationTimestamp:   &kubeconfigRequest.expirationTimestamp,
			ClientCertificateData: string(certificateSet.ClientCertificateData),
			ClientKeyData:         string(certificateSet.ClientKeyData),
		},
	}, nil
}

func (o *GetClientCertificateOptions) createKubeconfigRequest(ctx context.Context) (*kubeconfigRequestStatus, error) {
	logger := klog.FromContext(ctx)

	switch o.AccessLevel {
	case accessLevelAdmin:
		return createAdminKubeconfigRequest(
			ctx,
			o.GardenCoreV1Beta1RESTClient,
			o.ShootRef.Namespace,
			o.ShootRef.Name,
			o.KubeconfigExpirationSeconds,
			metav1.CreateOptions{},
		)
	case accessLevelViewer:
		return createViewerKubeconfigRequest(
			ctx,
			o.GardenCoreV1Beta1RESTClient,
			o.ShootRef.Namespace,
			o.ShootRef.Name,
			o.KubeconfigExpirationSeconds,
			metav1.CreateOptions{},
		)
	case accessLevelAuto:
		kubeconfigRequest, err := createAdminKubeconfigRequest(
			ctx,
			o.GardenCoreV1Beta1RESTClient,
			o.ShootRef.Namespace,
			o.ShootRef.Name,
			o.KubeconfigExpirationSeconds,
			metav1.CreateOptions{},
		)

		if apierrors.IsForbidden(err) {
			logger.V(4).Info("No permission to obtain admin kubeconfig. Falling back to obtaining viewer kubeconfig.", "error", err)

			kubeconfigRequest, err = createViewerKubeconfigRequest(
				ctx,
				o.GardenCoreV1Beta1RESTClient,
				o.ShootRef.Namespace,
				o.ShootRef.Name,
				o.KubeconfigExpirationSeconds,
				metav1.CreateOptions{},
			)
			if apierrors.IsForbidden(err) {
				return nil, fmt.Errorf("no permission to obtain either admin or viewer kubeconfig: %w", err)
			}
		}

		if err != nil {
			return nil, err
		}

		// Return the kubeconfigRequest which might be either admin or viewer type.
		return kubeconfigRequest, nil
	default:
		return nil, fmt.Errorf("invalid access level: %s", o.AccessLevel)
	}
}

// AllowedAccessLevels returns the allowed values for the access-level flag.
func (o *GetClientCertificateOptions) AllowedAccessLevels() []string {
	return []string{accessLevelAuto, accessLevelAdmin, accessLevelViewer}
}

func createAdminKubeconfigRequest(ctx context.Context, client rest.Interface, namespace string, shootName string, expirationSeconds int64, opts metav1.CreateOptions) (*kubeconfigRequestStatus, error) {
	adminKubeconfigRequest := &authenticationv1alpha1.AdminKubeconfigRequest{
		TypeMeta: metav1.TypeMeta{
			Kind:       "AdminKubeconfigRequest",
			APIVersion: authenticationv1alpha1.SchemeGroupVersion.String(),
		},
		Spec: authenticationv1alpha1.AdminKubeconfigRequestSpec{
			ExpirationSeconds: pointer.Int64(expirationSeconds),
		},
	}

	err := client.Post().
		Namespace(namespace).
		Resource("shoots").
		Name(shootName).
		SubResource("adminkubeconfig").
		VersionedParams(&opts, gardenscheme.ParameterCodec).
		Body(adminKubeconfigRequest).
		Do(ctx).
		Into(adminKubeconfigRequest)
	if err != nil {
		return nil, err
	}

	kubeconfigRequest := kubeconfigRequestStatus{
		kubeconfig:          adminKubeconfigRequest.Status.Kubeconfig,
		expirationTimestamp: adminKubeconfigRequest.Status.ExpirationTimestamp,
	}

	return &kubeconfigRequest, nil
}

func createViewerKubeconfigRequest(ctx context.Context, client rest.Interface, namespace string, shootName string, expirationSeconds int64, opts metav1.CreateOptions) (*kubeconfigRequestStatus, error) {
	viewerKubeconfigRequest := &authenticationv1alpha1.ViewerKubeconfigRequest{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ViewerKubeconfigRequest",
			APIVersion: authenticationv1alpha1.SchemeGroupVersion.String(),
		},
		Spec: authenticationv1alpha1.ViewerKubeconfigRequestSpec{
			ExpirationSeconds: pointer.Int64(expirationSeconds),
		},
	}

	err := client.Post().
		Namespace(namespace).
		Resource("shoots").
		Name(shootName).
		SubResource("viewerkubeconfig").
		VersionedParams(&opts, gardenscheme.ParameterCodec).
		Body(viewerKubeconfigRequest).
		Do(ctx).
		Into(viewerKubeconfigRequest)
	if err != nil {
		return nil, err
	}

	kubeconfigRequest := kubeconfigRequestStatus{
		kubeconfig:          viewerKubeconfigRequest.Status.Kubeconfig,
		expirationTimestamp: viewerKubeconfigRequest.Status.ExpirationTimestamp,
	}

	return &kubeconfigRequest, nil
}

func authInfoFromKubeconfigForCluster(kubeconfig []byte, cluster *clientauthenticationv1.Cluster) (*api.AuthInfo, error) {
	shootClientConfig, err := clientcmd.NewClientConfigFromBytes(kubeconfig)
	if err != nil {
		return nil, err
	}

	config, err := shootClientConfig.RawConfig()
	if err != nil {
		return nil, err
	}

	clusterName, err := clusterNameFromConfigForCluster(config, cluster)
	if err != nil {
		return nil, err
	}

	userName, err := userNameFromConfigForClusterName(config, clusterName)
	if err != nil {
		return nil, err
	}

	return authInfoFromConfigForUserName(config, userName)
}

func clusterNameFromConfigForCluster(config api.Config, cluster *clientauthenticationv1.Cluster) (string, error) {
	if cluster == nil {
		// fallback to cluster from current context (to support kubectl versions older v1.20.0)
		context := config.Contexts[config.CurrentContext]
		if context == nil {
			return "", fmt.Errorf("no context found for current context %s", config.CurrentContext)
		}

		return context.Cluster, nil
	}

	for name, c := range config.Clusters {
		if cluster.Server == c.Server {
			return name, nil
		}
	}

	return "", fmt.Errorf("no matching cluster found for server %s", cluster.Server)
}

func userNameFromConfigForClusterName(config api.Config, clusterName string) (string, error) {
	for _, c := range config.Contexts {
		if clusterName == c.Cluster {
			return c.AuthInfo, nil
		}
	}

	return "", fmt.Errorf("no matching context found for cluster name %s", clusterName)
}

func authInfoFromConfigForUserName(config api.Config, userName string) (*api.AuthInfo, error) {
	for user, a := range config.AuthInfos {
		if userName == user {
			return a, nil
		}
	}

	return nil, fmt.Errorf("no matching user config found for user name %s", userName)
}
