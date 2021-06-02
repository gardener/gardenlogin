/*
SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors

SPDX-License-Identifier: Apache-2.0
*/

package cmd_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"time"

	c "github.com/gardener/garden-login/cmd"
	"github.com/gardener/garden-login/internal/certificatecache"

	"github.com/gardener/gardener/pkg/apis/authentication"
	authenticationv1alpha1 "github.com/gardener/gardener/pkg/apis/authentication/v1alpha1"
	"github.com/gardener/gardener/pkg/utils/secrets"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/cli-runtime/pkg/resource"
	"k8s.io/client-go/pkg/apis/clientauthentication/v1beta1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/rest/fake"
)

var _ = Describe("GetClientCertificate", func() {
	var (
		codec runtime.Codec

		kubeconfig     string
		expirationTime time.Time
		validity       time.Duration

		ioStreams genericclioptions.IOStreams
		errOut    *bytes.Buffer
		out       *bytes.Buffer

		shootCaData []byte
		ec          v1beta1.ExecCredential
	)

	BeforeEach(func() {
		scheme := runtime.NewScheme()
		Expect(authenticationv1alpha1.AddToScheme(scheme)).To(Succeed())
		Expect(authentication.AddToScheme(scheme)).To(Succeed())
		codecs := serializer.NewCodecFactory(scheme)
		codec = codecs.LegacyCodec(authenticationv1alpha1.SchemeGroupVersion)

		ioStreams, _, out, errOut = genericclioptions.NewTestIOStreams()

		kubeconfig = `
apiVersion: v1
clusters:
- cluster:
    certificate-authority-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCi4uLgotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0t
    server: https://api.mycluster.myproject.foo
  name: shoot--myproject--mycluster
contexts:
- context:
    cluster: shoot--myproject--mycluster
    user: shoot--myproject--mycluster
  name: shoot--myproject--mycluster
current-context: shoot--myproject--mycluster
kind: Config
preferences: {}
users:
- name: shoot--myproject--mycluster
  user:
    client-certificate-data: Zm9v
    client-key-data: YmFy
`
		validity = 10 * time.Minute
		expirationTime = fakeNow().Add(10 * time.Minute)

		var err error
		shootCaData, err = base64.StdEncoding.DecodeString("LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCi4uLgotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0t")
		Expect(err).ToNot(HaveOccurred())

		epc := c.ExecPluginConfig{
			ShootRef: c.ShootRef{
				Namespace: "garden-myproject",
				Name:      "mycluster",
			},
			GardenClusterIdentity: "landscape-dev",
		}
		epcRaw, err := json.Marshal(epc)
		Expect(err).ToNot(HaveOccurred())

		ec = v1beta1.ExecCredential{
			TypeMeta: metav1.TypeMeta{
				Kind:       "ExecCredential",
				APIVersion: v1beta1.SchemeGroupVersion.String(),
			},
			Spec: v1beta1.ExecCredentialSpec{
				Cluster: &v1beta1.Cluster{
					Server:                   "https://api.mycluster.myproject.foo",
					CertificateAuthorityData: shootCaData,
					Config: runtime.RawExtension{
						Raw: epcRaw,
					},
				},
			},
		}
	})

	Context("GetClientCertificateOptions Validation", func() {
		var (
			o          c.GetClientCertificateOptions
			gotErr     error
			wantErrStr string
		)
		BeforeEach(func() {
			// valid GetClientCertificateOptions
			o = c.GetClientCertificateOptions{
				ShootCluster: &v1beta1.Cluster{
					Server:                   "foo",
					CertificateAuthorityData: []byte("foo"),
				},
				ShootRef: c.ShootRef{
					Namespace: "foo",
					Name:      "foo",
				},
				GardenClusterIdentity:            "foo",
				AdminKubeconfigExpirationSeconds: 42,
			}
			gotErr = nil
			wantErrStr = ""
		})

		AssertError := func() func() {
			return func() {
				Expect(gotErr).To(HaveOccurred())
				Expect(gotErr.Error()).To(Equal(wantErrStr))
			}
		}
		AssertSuccess := func() func() {
			return func() {
				Expect(gotErr).ToNot(HaveOccurred())
			}
		}

		Context("should not report an error on valid options", func() {
			BeforeEach(func() {
				gotErr = o.Validate()
				wantErrStr = ""
			})
			It("should not report an error on invalid options", AssertSuccess())
		})

		Context("should not report an error on invalid options", func() {
			Context("when name is not set", func() {
				BeforeEach(func() {
					o.ShootRef.Name = ""
					gotErr = o.Validate()
					wantErrStr = "name must be specified"
				})
				It("should not report an error", AssertError())
			})

			Context("when namespace is not set", func() {
				BeforeEach(func() {
					o.ShootRef.Namespace = ""
					gotErr = o.Validate()
					wantErrStr = "namespace must be specified"
				})
				It("should not report an error", AssertError())
			})

			Context("when cluster is not set", func() {
				BeforeEach(func() {
					o.ShootCluster = nil
					gotErr = o.Validate()
					wantErrStr = "cluster must be specified"
				})
				It("should not report an error", AssertError())
			})

			Context("when cluster server is not set", func() {
				BeforeEach(func() {
					o.ShootCluster.Server = ""
					gotErr = o.Validate()
					wantErrStr = "server must be specified"
				})
				It("should not report an error", AssertError())
			})

			Context("when certificate authority data is not set", func() {
				BeforeEach(func() {
					o.ShootCluster.CertificateAuthorityData = nil
					gotErr = o.Validate()
					wantErrStr = "certificate authority data must be specified"
				})
				It("should not report an error", AssertError())
			})
		})
	})

	Context("Tests expecting success", func() {
		var (
			caCert     *secrets.Certificate
			clientCert *secrets.Certificate
			key        certificatecache.Key
			f          *TestFactory
		)

		Context("KUBERNETES_EXEC_INFO is set", func() {
			BeforeEach(func() {
				execInfo, err := json.Marshal(ec)
				Expect(err).ToNot(HaveOccurred())
				os.Setenv("KUBERNETES_EXEC_INFO", string(execInfo))

				key = certificatecache.Key{
					ShootServer:           "https://api.mycluster.myproject.foo",
					ShootName:             "mycluster",
					ShootNamespace:        "garden-myproject",
					GardenClusterIdentity: "landscape-dev",
				}

				f = &TestFactory{
					gardenClusterIdentity: "landscape-dev",
					homeDirectoy:          "/Users/foo",
				}

				caCert = generateCaCert()
				clientCert = generateClientCert(fakeNow, caCert, validity)
			})

			AfterEach(func() {
				Expect(os.Unsetenv("KUBERNETES_EXEC_INFO")).To(Succeed())
			})

			It("Should return cached client certificate", func() {
				cmd := c.NewCmdGetClientCertificate(f, ioStreams)

				opts := c.NewGetClientCertificateOptions(ioStreams)
				opts.Clock = newFakeClock()

				err := opts.Complete(f, cmd, []string{})
				Expect(err).ToNot(HaveOccurred())

				err = opts.Validate()
				Expect(err).ToNot(HaveOccurred())

				fStore := newFakeStore()
				opts.CertificateCacheStore = &fStore

				By("Ensure valid certificate is found in certificate cache")
				cachedCertificateSet := certificatecache.CertificateSet{
					ClientCertificateData: clientCert.CertificatePEM,
					ClientKeyData:         clientCert.PrivateKeyPEM,
				}
				fStore.inMemory[key] = struct {
					certificateSet *certificatecache.CertificateSet
					err            error
				}{
					certificateSet: &cachedCertificateSet,
					err:            nil,
				}

				ctx, cancel := context.WithTimeout(context.Background(), validity)
				defer cancel()

				err = opts.RunGetClientCertificate(ctx)
				Expect(err).ToNot(HaveOccurred())

				By("Expecting cached certificate to be printed to out buffer")
				Expect(out.String()).To(Equal(fmt.Sprintf(
					`{"kind":"ExecCredential","apiVersion":"client.authentication.k8s.io/v1beta1","spec":{},"status":{"expirationTimestamp":%q,"clientCertificateData":%q,"clientKeyData":%q}}
`,
					expirationTime.Format(time.RFC3339),
					string(clientCert.CertificatePEM),
					string(clientCert.PrivateKeyPEM),
				)))
				Expect(errOut.String()).To(BeEmpty())
			})

			It("Should fetch the client certificate", func() {
				By("By using fake RESTClient")
				response := &authenticationv1alpha1.AdminKubeconfigRequest{
					Status: authenticationv1alpha1.AdminKubeconfigRequestStatus{
						Kubeconfig:          []byte(kubeconfig),
						ExpirationTimestamp: metav1.Time{Time: expirationTime},
					},
				}
				restClient := &fake.RESTClient{
					GroupVersion: struct {
						Group   string
						Version string
					}{Group: "", Version: "v1"},
					NegotiatedSerializer: resource.UnstructuredPlusDefaultContentConfig().NegotiatedSerializer,
					Client: fake.CreateHTTPClient(func(req *http.Request) (*http.Response, error) {
						switch req.Method {
						case "POST":
							switch req.URL.Path {
							case "/namespaces/garden-myproject/shoots/mycluster/adminkubeconfig":
								bodyAkr := &authenticationv1alpha1.AdminKubeconfigRequest{}
								BodyIntoObj(codec, req.Body, bodyAkr)
								wantExpirationSeconds := int64(42)
								Expect(bodyAkr.Spec.ExpirationSeconds).To(Equal(&wantExpirationSeconds))

								return &http.Response{StatusCode: http.StatusOK, Header: DefaultHeader(), Body: ObjBody(codec, response)}, nil
							default:
								Fail(fmt.Sprintf("unexpected request: %#v\n%#v", req.URL, req))
								return nil, nil
							}
						default:
							Fail(fmt.Sprintf("unexpected request: %s %#v\n%#v", req.Method, req.URL, req))
							return nil, nil
						}
					}),
				}
				f.restClient = restClient

				cmd := c.NewCmdGetClientCertificate(f, ioStreams)

				opts := c.NewGetClientCertificateOptions(ioStreams)
				opts.Clock = newFakeClock()

				err := opts.Complete(f, cmd, []string{})
				Expect(err).ToNot(HaveOccurred())

				err = opts.Validate()
				Expect(err).ToNot(HaveOccurred())

				fStore := newFakeStore()
				opts.CertificateCacheStore = &fStore
				opts.AdminKubeconfigExpirationSeconds = 42

				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()

				err = opts.RunGetClientCertificate(ctx)
				Expect(err).ToNot(HaveOccurred())

				By("Expecting no certificate to be printed to out buffer")
				Expect(out.String()).To(Equal(fmt.Sprintf(
					`{"kind":"ExecCredential","apiVersion":"client.authentication.k8s.io/v1beta1","spec":{},"status":{"expirationTimestamp":%q,"clientCertificateData":%q,"clientKeyData":%q}}
`,
					expirationTime.Format(time.RFC3339),
					"foo",
					"bar",
				)))
				Expect(errOut.String()).To(BeEmpty())

				By("Expecting certificate to be stored in cache")
				wantCertificateSet := certificatecache.CertificateSet{
					ClientCertificateData: []byte("foo"),
					ClientKeyData:         []byte("bar"),
				}
				Expect(fStore.inMemory[key]).To(Equal(struct {
					certificateSet *certificatecache.CertificateSet
					err            error
				}{
					certificateSet: &wantCertificateSet,
					err:            nil,
				}))
			})
		})
	})
})

func DefaultHeader() http.Header {
	header := http.Header{}
	header.Set("Content-Type", runtime.ContentTypeJSON)

	return header
}

func BodyIntoObj(codec runtime.Codec, rc io.ReadCloser, obj runtime.Object) {
	b, err := ioutil.ReadAll(rc)
	Expect(err).ToNot(HaveOccurred())
	Expect(runtime.DecodeInto(codec, b, obj)).To(Succeed())
}

func ObjBody(codec runtime.Codec, obj runtime.Object) io.ReadCloser {
	return ioutil.NopCloser(bytes.NewReader([]byte(runtime.EncodeOrDie(codec, obj))))
}

func generateClientCert(now func() time.Time, caCert *secrets.Certificate, validity time.Duration) *secrets.Certificate {
	csc := &secrets.CertificateSecretConfig{
		Name:         "foo",
		CommonName:   "foo",
		Organization: []string{user.SystemPrivilegedGroup},
		CertType:     secrets.ClientCert,
		Validity:     &validity,
		SigningCA:    caCert,
		Now:          now,
	}
	cert, err := csc.GenerateCertificate()
	Expect(err).ToNot(HaveOccurred())

	return cert
}

func generateCaCert() *secrets.Certificate {
	csc := &secrets.CertificateSecretConfig{
		Name:       "ca-test",
		CommonName: "ca-test",
		CertType:   secrets.CACert,
	}
	caCertificate, err := csc.GenerateCertificate()
	Expect(err).ToNot(HaveOccurred())

	return caCertificate
}

type TestFactory struct {
	restClient            rest.Interface
	gardenClusterIdentity string
	homeDirectoy          string
}

func (t *TestFactory) HomeDir() string {
	return t.homeDirectoy
}

func (t *TestFactory) RESTClient(gardenClusterIdentity string) (rest.Interface, error) {
	Expect(t.gardenClusterIdentity).To(Equal(gardenClusterIdentity))
	return t.restClient, nil
}

// fakeClock implements Clock interface
type fakeClock struct {
	fakeTime time.Time
}

func (f *fakeClock) Now() time.Time {
	return f.fakeTime
}

func newFakeClock() *fakeClock {
	return &fakeClock{fakeTime: fakeNow()}
}

func fakeNow() time.Time {
	t, err := time.Parse(time.RFC3339, "2017-12-14T23:34:00.000Z")
	Expect(err).ToNot(HaveOccurred())

	return t
}

func newFakeStore() fakeStore {
	return fakeStore{
		inMemory: make(map[certificatecache.Key]struct {
			certificateSet *certificatecache.CertificateSet
			err            error
		}),
	}
}

// fakeStore implements store.Interface interface
type fakeStore struct {
	inMemory map[certificatecache.Key]struct {
		certificateSet *certificatecache.CertificateSet
		err            error
	}
}

func (s *fakeStore) FindByKey(key certificatecache.Key) (*certificatecache.CertificateSet, error) {
	res, ok := s.inMemory[key]
	if !ok {
		return nil, errors.New("item not found")
	}

	return res.certificateSet, res.err
}

func (s *fakeStore) Save(key certificatecache.Key, certificateSet certificatecache.CertificateSet) error {
	res := s.inMemory[key]
	s.inMemory[key] = struct {
		certificateSet *certificatecache.CertificateSet
		err            error
	}{
		certificateSet: &certificateSet,
		err:            nil}

	return res.err
}
