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

	"encoding/json"

	apiv1 "k8s.io/api/core/v1"

	"bytes"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/simple-kubernetes-webhook/pkg/admission"
	admissionv1 "k8s.io/api/admission/v1"
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

var parameters ServerParameters

var (
	universalDeserializer = serializer.NewCodecFactory(runtime.NewScheme()).UniversalDeserializer()
)

var config *rest.Config
var clientSet *kubernetes.Clientset

func main() {

	useKubeConfig := os.Getenv("USE_KUBECONFIG")
	kubeConfigFilePath := os.Getenv("KUBECONFIG")

	flag.IntVar(&parameters.port, "port", 8443, "Webhook server port.")
	flag.StringVar(&parameters.certFile, "tlsCertFile", "/etc/webhook/certs/tls.crt", "File containing the x509 Certificate for HTTPS.")
	flag.StringVar(&parameters.keyFile, "tlsKeyFile", "/etc/webhook/certs/tls.key", "File containing the x509 private key to --tlsCertFile.")
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

	test()
	http.HandleFunc("/", HandleRoot)
	http.HandleFunc("/mutate", HandleMutate)
	http.HandleFunc("/validate", HandleValidate)
	log.Fatal(http.ListenAndServeTLS(":"+strconv.Itoa(parameters.port), parameters.certFile, parameters.keyFile, nil))
}

func HandleRoot(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("HandleRoot!"))
}

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
	labels["example-webhook"] = "it-worked"

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

	bytes, err := json.Marshal(&admissionReviewResponse)
	if err != nil {
		fmt.Errorf("marshaling response: %v", err)
	}

	w.Write(bytes)

}

// ServeValidatePods validates an admission request and then writes an admission
// review to `w`
func HandleValidate(w http.ResponseWriter, r *http.Request) {
	fmt.Errorf("dento de validate")
	logger := logrus.WithField("uri", r.RequestURI)
	logger.Debug("received validation request")

	in, err := parseRequest(*r)
	if err != nil {
		logger.Error(err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	adm := admission.Admitter{
		Logger:  logger,
		Request: in.Request,
	}

	out, err := adm.ValidatePodReview()
	if err != nil {
		e := fmt.Sprintf("could not generate admission response: %v", err)
		logger.Error(e)
		http.Error(w, e, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	jout, err := json.Marshal(out)
	if err != nil {
		e := fmt.Sprintf("could not parse admission response: %v", err)
		logger.Error(e)
		http.Error(w, e, http.StatusInternalServerError)
		return
	}

	logger.Debug("sending response")
	logger.Debugf("%s", jout)
	fmt.Fprintf(w, "%s", jout)
}

// ServeMutatePods returns an admission review with pod mutations as a json patch
// in the review response
func ServeMutatePods(w http.ResponseWriter, r *http.Request) {
	logger := logrus.WithField("uri", r.RequestURI)
	logger.Debug("received mutation request")

	in, err := parseRequest(*r)
	if err != nil {
		logger.Error(err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	adm := admission.Admitter{
		Logger:  logger,
		Request: in.Request,
	}

	out, err := adm.MutatePodReview()
	if err != nil {
		e := fmt.Sprintf("could not generate admission response: %v", err)
		logger.Error(e)
		http.Error(w, e, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	jout, err := json.Marshal(out)
	if err != nil {
		e := fmt.Sprintf("could not parse admission response: %v", err)
		logger.Error(e)
		http.Error(w, e, http.StatusInternalServerError)
		return
	}

	logger.Debug("sending response")
	logger.Debugf("%s", jout)
	fmt.Fprintf(w, "%s", jout)
}

// setLogger sets the logger using env vars, it defaults to text logs on
// debug level unless otherwise specified
func setLogger() {
	logrus.SetLevel(logrus.DebugLevel)

	lev := os.Getenv("LOG_LEVEL")
	if lev != "" {
		llev, err := logrus.ParseLevel(lev)
		if err != nil {
			logrus.Fatalf("cannot set LOG_LEVEL to %q", lev)
		}
		logrus.SetLevel(llev)
	}

	if os.Getenv("LOG_JSON") == "true" {
		logrus.SetFormatter(&logrus.JSONFormatter{})
	}
}

// parseRequest extracts an AdmissionReview from an http.Request if possible
func parseRequest(r http.Request) (*admissionv1.AdmissionReview, error) {
	if r.Header.Get("Content-Type") != "application/json" {
		return nil, fmt.Errorf("Content-Type: %q should be %q",
			r.Header.Get("Content-Type"), "application/json")
	}

	bodybuf := new(bytes.Buffer)
	bodybuf.ReadFrom(r.Body)
	body := bodybuf.Bytes()

	err := ioutil.WriteFile("/tmp/validate", body, 0644)
	if err != nil {
		panic(err.Error())
	}

	if len(body) == 0 {
		return nil, fmt.Errorf("admission request body is empty")
	}

	var a admissionv1.AdmissionReview

	if err := json.Unmarshal(body, &a); err != nil {
		return nil, fmt.Errorf("could not parse admission review request: %v", err)
	}

	if a.Request == nil {
		return nil, fmt.Errorf("admission review can't be used: Request field is nil")
	}

	return &a, nil
}
