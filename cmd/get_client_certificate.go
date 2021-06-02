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

	"github.com/gardener/garden-login/internal/certificatecache"
	"github.com/gardener/garden-login/internal/certificatecache/store"
	"github.com/gardener/garden-login/internal/cmd/util"

	authenticationv1alpha1 "github.com/gardener/gardener/pkg/apis/authentication/v1alpha1"
	gardenscheme "github.com/gardener/gardener/pkg/client/core/clientset/versioned/scheme"
	"github.com/mitchellh/go-homedir"
	"github.com/spf13/cobra"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	clientauthv1beta1 "k8s.io/client-go/pkg/apis/clientauthentication/v1beta1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/auth/exec"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/clientcmd/api"
	"k8s.io/klog/v2"
)

var (
	ioStreams = genericclioptions.IOStreams{
		In:     os.Stdin,
		Out:    os.Stdout,
		ErrOut: os.Stderr,
	}
	// getClientCertificateCmd represents the getClientCertificate command
	getClientCertificateCmd *cobra.Command
)

// ExecPluginConfig contains additional data which is needed for the
// garden-login plugin to authenticate against the shoot cluster
type ExecPluginConfig struct {
	// ShootRef references the shoot cluster
	ShootRef ShootRef `json:"shootRef"`
	// GardenClusterIdentity is the cluster identifier of the garden cluster.
	// See cluster-identity ConfigMap in kube-system namespace of the garden cluster
	GardenClusterIdentity string `json:"gardenClusterIdentity"`
}

// ShootRef references the shoot cluster by namespace and name
type ShootRef struct {
	// Namespace is the namespace of the shoot cluster
	Namespace string `json:"namespace"`
	// Namespace is the name of the shoot cluster
	Name string `json:"name"`
}

// GetClientCertificateOptions has the data required to perform the getClientCertificate operation
type GetClientCertificateOptions struct {
	// IOStreams provides the standard names for iostreams
	IOStreams genericclioptions.IOStreams
	// CertificateCacheStore is the store for accessing the certificatecache.CertificateSet items
	CertificateCacheStore store.Interface

	// Clock provides the current time
	Clock util.Clock

	// Common user flags

	// ShootCluster holds the data of the shoot kubernetes cluster.
	// The Server Server and CertificateAuthorityData must match with what is returned in the kubeconfig of the "shoots/adminkubeconfig" subresource.
	ShootCluster *clientauthv1beta1.Cluster
	// ShootRef references the shoot cluster for which the client certificate credentials should be obtained
	ShootRef ShootRef

	// GardenClusterIdentity is the cluster identifier of the garden cluster.
	// See cluster-identity ConfigMap in kube-system namespace of the garden cluster
	GardenClusterIdentity string

	// REST Client for the garden cluster
	GardenCoreV1Beta1RESTClient rest.Interface

	// CertificateCacheDir is the directory of the certificate cache
	CertificateCacheDir string

	// AdminKubeconfigExpirationSeconds defines the validity duration of the requested credential
	AdminKubeconfigExpirationSeconds int64
}

func init() {
	dir, err := homedir.Dir()
	if err != nil {
		klog.Errorf("could not determine home directory %v", err)
	}

	f := &util.FactoryImpl{
		HomeDirectory: dir,
	}

	getClientCertificateCmd = NewCmdGetClientCertificate(f, ioStreams)

	rootCmd.AddCommand(getClientCertificateCmd)
}

// NewGetClientCertificateOptions returns the options to perform the get-client-certificate command
func NewGetClientCertificateOptions(ioStreams genericclioptions.IOStreams) *GetClientCertificateOptions {
	return &GetClientCertificateOptions{
		IOStreams: ioStreams,
		Clock:     util.RealClock{},
	}
}

const (
	FlagGardenClusterIdentity = "garden-cluster-identity"
	FlagName                  = "name"
	FlagNamespace             = "namespace"
	FlagCertificateCacheDir   = "certificate-cache-dir"
	FlagExpirationSeconds     = "expiration-seconds"
)

// NewCmdGetClientCertificate returns the get-client-certificate cobra.Command
func NewCmdGetClientCertificate(f util.Factory, ioStreams genericclioptions.IOStreams) *cobra.Command {
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

	cmd.Flags().StringVar(&o.ShootRef.Name, FlagName, "", "Name of the shoot cluster")
	cmd.Flags().StringVar(&o.ShootRef.Namespace, FlagNamespace, "", "Namespace of the shoot cluster")
	cmd.Flags().StringVar(&o.GardenClusterIdentity, FlagGardenClusterIdentity, "", "Cluster identifier of the garden cluster")
	cmd.Flags().StringVar(&o.CertificateCacheDir, FlagCertificateCacheDir, filepath.Join(f.HomeDir(), ".kube", "cache", "garden-login"), "Directory of the certificate cache")
	cmd.Flags().Int64Var(&o.AdminKubeconfigExpirationSeconds, FlagExpirationSeconds, 900, "Validity duration of the requested credential")

	return cmd
}

// Complete adapts from the command line args to the data required.
func (o *GetClientCertificateOptions) Complete(f util.Factory, cmd *cobra.Command, args []string) error {
	obj, _, err := exec.LoadExecCredentialFromEnv()
	if err != nil {
		return err
	}

	cred, ok := obj.(*clientauthv1beta1.ExecCredential)
	if !ok {
		return fmt.Errorf("cannot convert to ExecCredential: %w", err)
	}

	var extension ExecPluginConfig

	if cred.Spec.Cluster.Config.Raw != nil {
		if err := json.Unmarshal(cred.Spec.Cluster.Config.Raw, &extension); err != nil {
			return err
		}
	}

	o.ShootCluster = cred.Spec.Cluster

	if o.GardenClusterIdentity == "" {
		o.GardenClusterIdentity = extension.GardenClusterIdentity
	}

	if o.ShootRef.Name == "" {
		o.ShootRef.Name = extension.ShootRef.Name
	}

	if o.ShootRef.Namespace == "" {
		o.ShootRef.Namespace = extension.ShootRef.Namespace
	}

	o.CertificateCacheStore = &store.Store{Dir: o.CertificateCacheDir}

	o.GardenCoreV1Beta1RESTClient, err = f.RESTClient(o.GardenClusterIdentity)
	if err != nil {
		return err
	}

	return nil
}

// Validate makes sure provided values for GetClientCertificateOptions are valid
func (o *GetClientCertificateOptions) Validate() error {
	if o.ShootCluster == nil {
		return errors.New("cluster must be specified")
	}

	if len(o.ShootCluster.Server) == 0 {
		return errors.New("server must be specified")
	}

	if len(o.ShootCluster.CertificateAuthorityData) == 0 {
		return errors.New("certificate authority data must be specified")
	}

	if len(o.ShootRef.Name) == 0 {
		return errors.New("name must be specified")
	}

	if len(o.ShootRef.Namespace) == 0 {
		return errors.New("namespace must be specified")
	}

	if len(o.GardenClusterIdentity) == 0 { // TODO or kubeconfig
		return errors.New("garden cluster identity must be specified")
	}

	return nil
}

// RunGetClientCertificate obtains the ExecCredential and writes it to the out stream.
func (o *GetClientCertificateOptions) RunGetClientCertificate(ctx context.Context) error {
	certificateCacheKey := certificatecache.Key{
		ShootServer:           o.ShootCluster.Server,
		ShootName:             o.ShootRef.Name,
		ShootNamespace:        o.ShootRef.Namespace,
		GardenClusterIdentity: o.GardenClusterIdentity,
	}

	cachedCertificateSet, err := o.CertificateCacheStore.FindByKey(certificateCacheKey)
	if err != nil {
		klog.V(4).Info("could not find a cached certificate: %w", err)
	}

	ec, err := o.getExecCredential(ctx, certificateCacheKey, cachedCertificateSet)
	if err != nil {
		return fmt.Errorf("failed to get ExecCredential: %w", err)
	}

	e := json.NewEncoder(o.IOStreams.Out)
	if err := e.Encode(ec); err != nil {
		return fmt.Errorf("could not write the ExecCredential: %w", err)
	}

	return nil
}

func (o *GetClientCertificateOptions) getExecCredential(ctx context.Context, certificateCacheKey certificatecache.Key, cachedCertificateSet *certificatecache.CertificateSet) (*clientauthv1beta1.ExecCredential, error) {
	if cachedCertificateSet != nil {
		certPem, _ := pem.Decode([]byte(cachedCertificateSet.ClientCertificateData))
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
			klog.V(4).Info("valid certificate in cache")

			return &clientauthv1beta1.ExecCredential{
				TypeMeta: metav1.TypeMeta{
					APIVersion: clientauthv1beta1.SchemeGroupVersion.String(),
					Kind:       "ExecCredential",
				},
				Status: &clientauthv1beta1.ExecCredentialStatus{
					ExpirationTimestamp:   &metav1.Time{Time: certificate.NotAfter},
					ClientCertificateData: string(cachedCertificateSet.ClientCertificateData),
					ClientKeyData:         string(cachedCertificateSet.ClientKeyData),
				},
			}, nil
		}

		klog.V(4).Info("the cached certificate is expired")
	}

	adminKubeconfigRequest := &authenticationv1alpha1.AdminKubeconfigRequest{
		TypeMeta: metav1.TypeMeta{
			Kind:       "AdminKubeconfigRequest",
			APIVersion: authenticationv1alpha1.SchemeGroupVersion.String(),
		},
		Spec: authenticationv1alpha1.AdminKubeconfigRequestSpec{
			ExpirationSeconds: &o.AdminKubeconfigExpirationSeconds,
		},
	}

	adminKubeconfigRequest, err := createAdminKubeconfigRequest(
		ctx,
		o.GardenCoreV1Beta1RESTClient,
		o.ShootRef.Namespace,
		o.ShootRef.Name,
		adminKubeconfigRequest,
		metav1.CreateOptions{},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to request admin kubeconfig: %w", err)
	}

	userConfig, err := authInfoFromKubeconfigForCluster(adminKubeconfigRequest.Status.Kubeconfig, o.ShootCluster)
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

	return &clientauthv1beta1.ExecCredential{
		TypeMeta: metav1.TypeMeta{
			APIVersion: clientauthv1beta1.SchemeGroupVersion.String(),
			Kind:       "ExecCredential",
		},
		Status: &clientauthv1beta1.ExecCredentialStatus{
			ExpirationTimestamp:   &adminKubeconfigRequest.Status.ExpirationTimestamp,
			ClientCertificateData: string(certificateSet.ClientCertificateData),
			ClientKeyData:         string(certificateSet.ClientKeyData),
		},
	}, nil
}

func createAdminKubeconfigRequest(ctx context.Context, client rest.Interface, namespace string, shootName string, adminKubeconfigRequest *authenticationv1alpha1.AdminKubeconfigRequest, opts metav1.CreateOptions) (*authenticationv1alpha1.AdminKubeconfigRequest, error) {
	result := &authenticationv1alpha1.AdminKubeconfigRequest{}

	err := client.Post().
		Namespace(namespace).
		Resource("shoots").
		Name(shootName).
		SubResource("adminkubeconfig").
		VersionedParams(&opts, gardenscheme.ParameterCodec).
		Body(adminKubeconfigRequest).
		Do(ctx).
		Into(result)
	if err != nil {
		return nil, err
	}

	return result, nil
}

func authInfoFromKubeconfigForCluster(kubeconfig []byte, cluster *clientauthv1beta1.Cluster) (*api.AuthInfo, error) {
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

func clusterNameFromConfigForCluster(config api.Config, cluster *clientauthv1beta1.Cluster) (string, error) {
	for name, c := range config.Clusters {
		if cluster.Server == c.Server &&
			apiequality.Semantic.DeepEqual(cluster.CertificateAuthorityData, c.CertificateAuthorityData) {
			return name, nil
		}
	}

	return "", fmt.Errorf("no matching cluster found for server %s and certificate-authority-data", cluster.Server)
}

func userNameFromConfigForClusterName(config api.Config, clusterName string) (string, error) {
	for name, c := range config.Contexts {
		if clusterName == c.Cluster {
			return name, nil
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
