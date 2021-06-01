module github.com/gardener/garden-login

go 1.16

require (
	github.com/Masterminds/goutils v1.1.1 // indirect
	github.com/gardener/gardener v1.24.0
	github.com/iancoleman/strcase v0.1.3
	github.com/mitchellh/copystructure v1.2.0 // indirect
	github.com/mitchellh/go-homedir v1.1.0
	github.com/onsi/ginkgo v1.14.2
	github.com/onsi/gomega v1.10.5
	github.com/spf13/cobra v1.1.3
	github.com/spf13/pflag v1.0.5
	github.com/spf13/viper v1.7.1
	gopkg.in/yaml.v3 v3.0.0-20200615113413-eeeca48fe776
	k8s.io/apimachinery v0.20.7
	k8s.io/apiserver v0.20.7
	k8s.io/cli-runtime v0.20.7
	k8s.io/client-go v11.0.1-0.20190409021438-1a26190bd76a+incompatible
	k8s.io/component-base v0.20.7
	k8s.io/klog/v2 v2.8.0
)

replace k8s.io/client-go => k8s.io/client-go v0.20.7
