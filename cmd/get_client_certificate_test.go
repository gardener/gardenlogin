/*
SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors

SPDX-License-Identifier: Apache-2.0
*/

package cmd_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/gardener/gardener/pkg/apis/authentication"
	authenticationv1alpha1 "github.com/gardener/gardener/pkg/apis/authentication/v1alpha1"
	"github.com/gardener/gardener/pkg/utils/secrets"
	"github.com/gardener/gardener/pkg/utils/test"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/pkg/apis/clientauthentication/v1beta1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/rest/fake"
	"k8s.io/utils/clock/testing"

	c "github.com/gardener/gardenlogin/cmd"
	"github.com/gardener/gardenlogin/internal/certificatecache"
	"github.com/gardener/gardenlogin/internal/certificatecache/store"
	"github.com/gardener/gardenlogin/internal/cmd/util"
)

var _ = Describe("GetClientCertificate", func() {
	var (
		codecs serializer.CodecFactory
		codec  runtime.Codec

		kubeconfig     string
		expirationTime time.Time
		validity       time.Duration

		ioStreams util.IOStreams
		errOut    *util.SafeBytesBuffer
		out       *util.SafeBytesBuffer

		shootCaData []byte
		ec          v1beta1.ExecCredential
	)

	BeforeEach(func() {
		scheme := runtime.NewScheme()
		Expect(authenticationv1alpha1.AddToScheme(scheme)).To(Succeed())
		Expect(authentication.AddToScheme(scheme)).To(Succeed())
		codecs = serializer.NewCodecFactory(scheme)
		codec = codecs.LegacyCodec(authenticationv1alpha1.SchemeGroupVersion)

		ioStreams, _, out, errOut = util.NewTestIOStreams()

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

			Context("KUBERNETES_EXEC_INFO is unset", func() {
				BeforeEach(func() {
					Expect(os.Unsetenv("KUBERNETES_EXEC_INFO")).To(Succeed())
				})

				Describe("when cluster is not set", func() {
					BeforeEach(func() {
						o.ShootCluster = nil
						gotErr = o.Validate()
					})
					It("should not report an error", AssertSuccess())
				})
			})
		})

		Context("should not report an error on invalid options", func() {
			Describe("when name is not set", func() {
				BeforeEach(func() {
					o.ShootRef.Name = ""
					gotErr = o.Validate()
					wantErrStr = "name must be specified. Hint: update kubectl in case you are using a version older than v1.20.0"
				})
				It("should report an error", AssertError())
			})

			Describe("when namespace is not set", func() {
				BeforeEach(func() {
					o.ShootRef.Namespace = ""
					gotErr = o.Validate()
					wantErrStr = "namespace must be specified"
				})
				It("should report an error", AssertError())
			})

			Describe("when GardenClusterIdentity is not set", func() {
				BeforeEach(func() {
					o.GardenClusterIdentity = ""
					gotErr = o.Validate()
					wantErrStr = "garden cluster identity must be specified"
				})
				It("should report an error", AssertError())
			})

			Context("KUBERNETES_EXEC_INFO is set", func() {
				BeforeEach(func() {
					Expect(os.Setenv("KUBERNETES_EXEC_INFO", "dummy")).To(Succeed())
				})

				Describe("when cluster is not set", func() {
					BeforeEach(func() {
						o.ShootCluster = nil
						gotErr = o.Validate()
						wantErrStr = "cluster must be specified"
					})
					It("should report an error", AssertError())
				})

				Describe("when cluster server is not set", func() {
					BeforeEach(func() {
						o.ShootCluster.Server = ""
						gotErr = o.Validate()
						wantErrStr = "server must be specified"
					})
					It("should report an error", AssertError())
				})
			})
		})
	})

	Context("Tests expecting success", func() {
		var (
			caCert     *secrets.Certificate
			clientCert *secrets.Certificate
			storeKey   certificatecache.Key
			f          *TestFactory
			cmd        *cobra.Command
			restClient *fake.RESTClient
		)

		BeforeEach(func() {
			DeferCleanup(test.WithVar(&secrets.Clock, testing.NewFakeClock(fakeNow())))

			storeKey = certificatecache.Key{
				ShootServer:           "https://api.mycluster.myproject.foo",
				ShootName:             "mycluster",
				ShootNamespace:        "garden-myproject",
				GardenClusterIdentity: "landscape-dev",
			}

			f = &TestFactory{
				gardenClusterIdentity: "landscape-dev",
				homeDirectoy:          "/Users/foo",
				clock:                 newFakeClock(),
				store:                 newFakeStore(),
			}

			cmd = c.NewCmdGetClientCertificate(f, ioStreams)

			caCert = generateCaCert()
			clientCert = generateClientCert(caCert, validity)

			response := &authenticationv1alpha1.AdminKubeconfigRequest{
				Status: authenticationv1alpha1.AdminKubeconfigRequestStatus{
					Kubeconfig:          []byte(kubeconfig),
					ExpirationTimestamp: metav1.Time{Time: expirationTime},
				},
			}
			restClient = &fake.RESTClient{
				GroupVersion: struct {
					Group   string
					Version string
				}{Group: "", Version: "v1"},
				NegotiatedSerializer: codecs.WithoutConversion(),
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
		})

		Context("KUBERNETES_EXEC_INFO is set", func() {
			BeforeEach(func() {
				execInfo, err := json.Marshal(ec)
				Expect(err).ToNot(HaveOccurred())
				Expect(os.Setenv("KUBERNETES_EXEC_INFO", string(execInfo))).To(Succeed())
			})

			AfterEach(func() {
				Expect(os.Unsetenv("KUBERNETES_EXEC_INFO")).To(Succeed())
			})

			It("Should return cached client certificate", func() {
				// a rest client is not needed for this test
				f.restClient = nil

				By("Ensure valid certificate is found in certificate cache")
				cachedCertificateSet := certificatecache.CertificateSet{
					ClientCertificateData: clientCert.CertificatePEM,
					ClientKeyData:         clientCert.PrivateKeyPEM,
				}
				f.store.inMemory[storeKey] = struct {
					certificateSet *certificatecache.CertificateSet
					err            error
				}{
					certificateSet: &cachedCertificateSet,
					err:            nil,
				}

				By("executing the command")
				Expect(cmd.Execute()).To(Succeed())

				By("Expecting cached certificate to be printed to out buffer")
				Expect(out.String()).To(Equal(fmt.Sprintf(
					`{"kind":"ExecCredential","apiVersion":"client.authentication.k8s.io/v1beta1","spec":{"interactive":false},"status":{"expirationTimestamp":%q,"clientCertificateData":%q,"clientKeyData":%q}}
`,
					expirationTime.Format(time.RFC3339),
					string(clientCert.CertificatePEM),
					string(clientCert.PrivateKeyPEM),
				)))
				Expect(errOut.String()).To(BeEmpty())
			})

			It("Should fetch the client certificate", func() {
				By("By using fake RESTClient")
				f.restClient = restClient

				By("executing the command")
				Expect(cmd.ParseFlags([]string{"--expiration-seconds=42"})).To(Succeed())
				Expect(cmd.Execute()).To(Succeed())

				By("Expecting certificate to be printed to out buffer")
				Expect(out.String()).To(Equal(fmt.Sprintf(
					`{"kind":"ExecCredential","apiVersion":"client.authentication.k8s.io/v1beta1","spec":{"interactive":false},"status":{"expirationTimestamp":%q,"clientCertificateData":%q,"clientKeyData":%q}}
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
				Expect(f.store.inMemory[storeKey]).To(Equal(struct {
					certificateSet *certificatecache.CertificateSet
					err            error
				}{
					certificateSet: &wantCertificateSet,
					err:            nil,
				}))
			})
		})

		Context("accepting arguments only - support for kubectl versions < 1.20.0", func() {
			BeforeEach(func() {
				Expect(os.Unsetenv("KUBERNETES_EXEC_INFO")).To(Succeed())
				storeKey.ShootServer = ""
			})

			It("Should return cached client certificate", func() {
				// a rest client is not needed for this test
				f.restClient = nil

				By("Ensure valid certificate is found in certificate cache")
				cachedCertificateSet := certificatecache.CertificateSet{
					ClientCertificateData: clientCert.CertificatePEM,
					ClientKeyData:         clientCert.PrivateKeyPEM,
				}
				f.store.inMemory[storeKey] = struct {
					certificateSet *certificatecache.CertificateSet
					err            error
				}{
					certificateSet: &cachedCertificateSet,
					err:            nil,
				}

				By("executing the command")
				args := []string{
					"--garden-cluster-identity=landscape-dev",
					"--name=mycluster",
					"--namespace=garden-myproject",
				}
				Expect(cmd.ParseFlags(args)).To(Succeed())
				Expect(cmd.Execute()).To(Succeed())

				By("Expecting cached certificate to be printed to out buffer")
				Expect(out.String()).To(Equal(fmt.Sprintf(
					`{"kind":"ExecCredential","apiVersion":"client.authentication.k8s.io/v1beta1","spec":{"interactive":false},"status":{"expirationTimestamp":%q,"clientCertificateData":%q,"clientKeyData":%q}}
`,
					expirationTime.Format(time.RFC3339),
					string(clientCert.CertificatePEM),
					string(clientCert.PrivateKeyPEM),
				)))
				Expect(errOut.String()).To(BeEmpty())
			})

			It("Should fetch the client certificate", func() {
				By("By using fake RESTClient")
				f.restClient = restClient

				By("executing the command")
				args := []string{
					"--garden-cluster-identity=landscape-dev",
					"--name=mycluster",
					"--namespace=garden-myproject",
					"--expiration-seconds=42",
				}
				Expect(cmd.ParseFlags(args)).To(Succeed())
				Expect(cmd.Execute()).To(Succeed())

				By("Expecting certificate to be printed to out buffer")
				Expect(out.String()).To(Equal(fmt.Sprintf(
					`{"kind":"ExecCredential","apiVersion":"client.authentication.k8s.io/v1beta1","spec":{"interactive":false},"status":{"expirationTimestamp":%q,"clientCertificateData":%q,"clientKeyData":%q}}
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
				Expect(f.store.inMemory[storeKey]).To(Equal(struct {
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
	b, err := io.ReadAll(rc)
	Expect(err).ToNot(HaveOccurred())
	Expect(runtime.DecodeInto(codec, b, obj)).To(Succeed())
}

func ObjBody(codec runtime.Codec, obj runtime.Object) io.ReadCloser {
	return io.NopCloser(bytes.NewReader([]byte(runtime.EncodeOrDie(codec, obj))))
}

func generateClientCert(caCert *secrets.Certificate, validity time.Duration) *secrets.Certificate {
	csc := &secrets.CertificateSecretConfig{
		Name:         "foo",
		CommonName:   "foo",
		Organization: []string{"system:masters"},
		CertType:     secrets.ClientCert,
		Validity:     &validity,
		SigningCA:    caCert,
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
	clock                 *fakeClock
	restClient            rest.Interface
	gardenClusterIdentity string
	homeDirectoy          string
	store                 *fakeStore
}

var _ util.Factory = &TestFactory{}

func (t *TestFactory) Clock() util.Clock {
	return t.clock
}

func (t *TestFactory) HomeDir() string {
	return t.homeDirectoy
}

func (t *TestFactory) RESTClient(gardenClusterIdentity string) (rest.Interface, error) {
	Expect(t.gardenClusterIdentity).To(Equal(gardenClusterIdentity))
	return t.restClient, nil
}

func (t *TestFactory) CertificateStore(_ string) store.Interface {
	return t.store
}

// fakeClock implements Clock interface.
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

func newFakeStore() *fakeStore {
	return &fakeStore{
		inMemory: make(map[certificatecache.Key]struct {
			certificateSet *certificatecache.CertificateSet
			err            error
		}),
	}
}

// fakeStore implements store.Interface interface.
type fakeStore struct {
	inMemory map[certificatecache.Key]struct {
		certificateSet *certificatecache.CertificateSet
		err            error
	}
}

var _ store.Interface = &fakeStore{}

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
		err:            nil,
	}

	return res.err
}
