
# Introduction to Kubernetes Admission controllers

[Admission Webhook](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/#what-are-admission-webhooks)

<hr/>

## Create TLS certificate to webhook
<hr/>

In order for our webhook to be invoked by Kubernetes, we need a TLS certificate.<br/>
In this demo I'll be using a self signed cert. <br/>
It's ok for development, but for production I would recommend using a real certificate instead. <br/>

## TLS certificate for Webhook

We'll use a very handy CloudFlare SSL tool in a docker container to get this done.

```
docker run -it --rm -v ${PWD}:/work -w /work debian bash

apt-get update && apt-get install -y curl &&
curl -L https://github.com/cloudflare/cfssl/releases/download/v1.5.0/cfssl_1.5.0_linux_amd64 -o /usr/local/bin/cfssl && \
curl -L https://github.com/cloudflare/cfssl/releases/download/v1.5.0/cfssljson_1.5.0_linux_amd64 -o /usr/local/bin/cfssljson && \
chmod +x /usr/local/bin/cfssl && \
chmod +x /usr/local/bin/cfssljson

#generate ca in /tmp
cfssl gencert -initca ./tls/ca-csr.json | cfssljson -bare /tmp/ca

#generate certificate in /tmp
cfssl gencert \
  -ca=/tmp/ca.pem \
  -ca-key=/tmp/ca-key.pem \
  -config=./tls/ca-config.json \
  -hostname="example-webhook,example-webhook.default.svc.cluster.local,example-webhook.default.svc,localhost,127.0.0.1" \
  -profile=default \
  ./tls/ca-csr.json | cfssljson -bare /tmp/example-webhook

#make a secret
cat <<EOF > ./tls/example-webhook-tls.yaml
apiVersion: v1
kind: Secret
metadata:
  name: example-webhook-tls
type: Opaque
data:
  tls.crt: $(cat /tmp/example-webhook.pem | base64 | tr -d '\n')
  tls.key: $(cat /tmp/example-webhook-key.pem | base64 | tr -d '\n') 
EOF

#generate CA Bundle + inject into template
ca_pem_b64="$(openssl base64 -A <"/tmp/ca.pem")"

sed -e 's@${CA_PEM_B64}@'"$ca_pem_b64"'@g' <"webhook-template.yaml" \
    > webhook.yaml
```


After the above, we should have: <br/>
* a Webhook YAML file
* CA Bundle for signing new TLS certificates
* a TLS certificate (Kubernetes secret)
<br/>

## Create API for webhook
The code on Golang language is native of the Kubernetes and use the same library that development of Kubernetes and the cli kubectl.

The below code will represent the Mutating Webhook and ValidatingWebhook

### The first block have the package name and import the library necessary for build
````
package main

import (
	"log"
	"net/http"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"

	"fmt"
	"os"
	"path/filepath"

	"k8s.io/client-go/kubernetes"
	rest "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"

	"flag"
	"io/ioutil"
	"strconv"

	"errors"

	"k8s.io/api/admission/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"encoding/json"

	apiv1 "k8s.io/api/core/v1"

	"bytes"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/simple-kubernetes-webhook/pkg/admission"
	admissionv1 "k8s.io/api/admission/v1"
)
```

### The second block define the variables, constants and structu that we will use
````


var (
	tlscert, tlskey string
    universalDeserializer = serializer.NewCodecFactory(runtime.NewScheme()).UniversalDeserializer()
    config *rest.Config
    clientSet *kubernetes.Clientset
    parameters ServerParameters
)


type ServerParameters struct {
	port     int    // webhook server port
	certFile string // path to the x509 certificate for https
	keyFile  string // path to the x509 private key matching `CertFile`
}

type patchOperation struct {
	Op    string      `json:"op"`
	Path  string      `json:"path"`
	Value interface{} `json:"value,omitempty"`
}

// Namespace struct for parsing
type Namespace struct {
	Metadata Metadata `json:"metadata"`
}

// Metadata struct for parsing
type Metadata struct {
	Name   string            `json:"name"`
	Labels map[string]string `json:"labels"`
}

const (
	// InvalidMessage will be return to the user.
	InvalidMessage = "namespace missing required team label"
	requiredLabel  = "team"
	port           = ":8444"
)



```

### Third block function main
The steps of the function main
- Load the certificates
- Validate if connect in Kubernetes by kueconfig or library in cluter
- Start the webserver

```
func main() {

	//	go another()
	useKubeConfig := os.Getenv("USE_KUBECONFIG")
	kubeConfigFilePath := os.Getenv("KUBECONFIG")

	flag.IntVar(&parameters.port, "port", 8443, "Webhook server port.")
	flag.StringVar(&parameters.certFile, "tlsCertFile", "/etc/webhook/certs/tls.crt", "File containing the x509 Certificate for HTTPS.")
	flag.StringVar(&parameters.keyFile, "tlsKeyFile", "/etc/webhook/certs/tls.key", "File containing the x509 private key to --tlsCertFile.")
	// flag.StringVar(&parameters.certFile, "tlsCertFile", "/tmp/tls/tls.crt", "File containing the x509 Certificate for HTTPS.")
	// flag.StringVar(&parameters.keyFile, "tlsKeyFile", "/tmp/tls/tls.key", "File containing the x509 private key to --tlsCertFile.")
	flag.Parse()

	if len(useKubeConfig) == 0 {
		// default to service account in cluster token
		c, err := rest.InClusterConfig()
		if err != nil {
			panic(err.Error())
		}
		config = c
	} else {
		//load from a kube config
		var kubeconfig string

		if kubeConfigFilePath == "" {
			if home := homedir.HomeDir(); home != "" {
				kubeconfig = filepath.Join(home, ".kube", "config")
			}
		} else {
			kubeconfig = kubeConfigFilePath
		}

		fmt.Println("kubeconfig: " + kubeconfig)

		c, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			panic(err.Error())
		}
		config = c
	}

	cs, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err.Error())
	}
	clientSet = cs

	http.HandleFunc("/", HandleRoot)
	http.HandleFunc("/mutate", HandleMutate)
	http.HandleFunc("/validate", HandleValidate)
	http.HandleFunc("/validate-pods", HandleValidatePods)
	log.Fatal(http.ListenAndServeTLS(":"+strconv.Itoa(parameters.port), parameters.certFile, parameters.keyFile, nil))
}
```

### four block of the mutate
The mutate recive the json of object and verify the fields baeing able change the fields or block the request. After the treat the object return the request with changed.
In this exemple we are incluing the lable **mylable: it-worked** 

```
func HandleMutate(w http.ResponseWriter, r *http.Request) {

	body, err := ioutil.ReadAll(r.Body)
	err = ioutil.WriteFile("/tmp/request", body, 0644)
	if err != nil {
		panic(err.Error())
	}

	var admissionReviewReq v1beta1.AdmissionReview

	if _, _, err := universalDeserializer.Decode(body, nil, &admissionReviewReq); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Errorf("could not deserialize request: %v", err)
	} else if admissionReviewReq.Request == nil {
		w.WriteHeader(http.StatusBadRequest)
		errors.New("malformed admission review: request is nil")
	}

	fmt.Printf("Type: %v \t Event: %v \t Name: %v \n",
		admissionReviewReq.Request.Kind,
		admissionReviewReq.Request.Operation,
		admissionReviewReq.Request.Name,
	)

	var pod apiv1.Pod

	err = json.Unmarshal(admissionReviewReq.Request.Object.Raw, &pod)

	if err != nil {
		fmt.Errorf("could not unmarshal pod on admission request: %v", err)
	}

	var patches []patchOperation

	labels := pod.ObjectMeta.Labels
	labels["mylabel"] = "it-worked"

	patches = append(patches, patchOperation{
		Op:    "add",
		Path:  "/metadata/labels",
		Value: labels,
	})

	patchBytes, err := json.Marshal(patches)

	if err != nil {
		fmt.Errorf("could not marshal JSON patch: %v", err)
	}

	admissionReviewResponse := v1beta1.AdmissionReview{
		Response: &v1beta1.AdmissionResponse{
			UID:     admissionReviewReq.Request.UID,
			Allowed: true,
		},
	}

	admissionReviewResponse.Response.Patch = patchBytes
	admissionReviewResponse.Response.Result = &metav1.Status{
		Message: InvalidMessage + " then pod name is: " + pod.ObjectMeta.Name + " not authorized to deploy",
	}

	bytes, err := json.Marshal(&admissionReviewResponse)
	if err != nil {
		fmt.Errorf("marshaling response: %v", err)
	}

	w.Write(bytes)

}
```

### Five block check if namespace has tha label team if haven`t the request is denied

```
func HandleValidate(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("In function validate namespace\n")
	arReview := v1beta1.AdmissionReview{}
	if err := json.NewDecoder(r.Body).Decode(&arReview); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	} else if arReview.Request == nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	raw := arReview.Request.Object.Raw

	ns := Namespace{}
	if err := json.Unmarshal(raw, &ns); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	} else if ns.Metadata.isEmpty() {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	arReview.Response = &v1beta1.AdmissionResponse{
		UID:     arReview.Request.UID,
		Allowed: true,
	}

	if len(ns.Metadata.Labels) == 0 || ns.Metadata.Labels[requiredLabel] == "" {
		arReview.Response.Allowed = false
		arReview.Response.Result = &metav1.Status{
			Message: InvalidMessage + " namespace name is: " + ns.Metadata.Name,
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(&arReview)
}
```

### The examples is possible to improve your environment:

1. Check if deploy has the specific label
```
namespaceSelector:
    matchExpressions:
    - key: environment
        operator: In
        values: ["prod","staging"]
```

2. Inject the sidecar equal the ISTIo
``` 
  namespaceSelector:
    matchExpressions:
    - key: istio-injection
      operator: DoesNotExist
    - key: istio.io/rev
      operator: DoesNotExist
  objectSelector:
    matchExpressions:
    - key: sidecar.istio.io/inject
      operator: In
      values:
      - "true"
    - key: istio.io/rev
      operator: DoesNotExist
```

3. If the cotainer content the privileged
```
 match:
    scope: Namespaced
    kinds:
    - apiGroups: ["*"]
      kinds: ["Pod"]
    excludedNamespaces: ["system"]
  location: "spec.containers[name:*].securityContext.privileged"
````

4. If the deployment content the resources limits or requests
```
 match:
    scope: Namespaced
    kinds:
    - apiGroups: ["*"]
      kinds: ["Pod"]
    excludedNamespaces: ["system"]
  location: "spec.containers[*].resources"
````

 