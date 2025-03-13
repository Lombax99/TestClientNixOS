package logic

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/securityresearchlab/nebula-est/nest_service/pkg/models"
	"github.com/slackhq/nebula/cert"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

var (
	Nest_service_ip    string = "20.71.180.246"
	Nest_service_port  string = "8080"
	Bin_folder         string = "bin/"
	Nebula_auth        string = "config/secret.hmac"
	Conf_folder        string = "./"
	Hostname           string = "nest_client_lin_64"
	Rekey              bool   = true                        // It indicates if the Nebula key pair has to be regenerated for the new Nebula certificate
	Enroll_chan               = make(chan time.Duration, 2) // buffer of two to avoid blocking i think, most of the time 1 would be enough
	Nebula_conf_folder string = "/home/lombax/nest/config/nebula/"
	Nest_certificate   string = "config/tls/nest_service-crt.pem"
	File_extension     string = ""
)

// func reenrollAfter(crt cert.NebulaCertificate) { // previous version
func reenrollAfter(crt *cert.NebulaCertificate) {
	// update the ncsr_status file with the status "Completed" and the expiration date of the certificate
	os.WriteFile(Conf_folder+"ncsr_status", []byte("Completed\n"+crt.Details.NotAfter.String()), 0600)
	// schedule the reenrollment for the expiration date of the certificate
	Enroll_chan <- time.Until(crt.Details.NotAfter)
}

// SetupTLSClient returns a client with the TLS configuration that can be used to send requests to the NEST service
func setupTLSClient() *http.Client {
	caCert, err := os.ReadFile(Nest_certificate)
	if err != nil {
		fmt.Println("Error in reading NEST certificate: " + err.Error())
		return nil
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion:               tls.VersionTLS12,
			MaxVersion:               tls.VersionTLS13,
			PreferServerCipherSuites: true,
			CurvePreferences:         []tls.CurveID{tls.X25519, tls.CurveP256},
			CipherSuites: []uint16{
				tls.TLS_AES_256_GCM_SHA384,
				tls.TLS_CHACHA20_POLY1305_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			},
			RootCAs: caCertPool},
	}
	client := &http.Client{Transport: tr}
	return client
}

// GetCSRResponse unmarshals the response from the NEST service into a NebulaCsrResponse struct
func getCSRResponse(response_bytes []byte) (*models.NebulaCsrResponse, error) {
	raw_csr_response := &models.RawNebulaCsrResponse{}
	csr_response := &models.NebulaCsrResponse{}
	var raw_csr_response_bytes []byte

	if json.Unmarshal(response_bytes, &raw_csr_response_bytes) != nil {
		fmt.Println("There was an error unmarshalling json response")
		return nil, &models.ApiError{Code: 500, Message: "There was an error unmarshalling json response"}
	}
	if proto.Unmarshal(raw_csr_response_bytes, raw_csr_response) != nil {
		fmt.Println("There was an error unmarshalling raw_csr_response_bytes")
		return nil, &models.ApiError{Code: 500, Message: "There was an error unmarshalling raw_csr_response_bytes"}
	}
	csr_response.NebulaConf = raw_csr_response.NebulaConf
	csr_response.NebulaPrivateKey = raw_csr_response.NebulaPrivateKey
	if raw_csr_response.NebulaPath != nil {
		csr_response.NebulaPath = *raw_csr_response.NebulaPath
	}

	raw_cert_bytes, err := proto.Marshal(raw_csr_response.NebulaCert)
	if err != nil {
		fmt.Println("There was an error marshalling raw_csr_response.NebulaCert" + err.Error())
		return nil, &models.ApiError{Code: 500, Message: "There was an error unmarshalling json response"}
	}

	crt, err := cert.UnmarshalNebulaCertificate(raw_cert_bytes)
	if err != nil {
		fmt.Println("There was an error unmarshalling raw_cert_bytes" + err.Error())
		return nil, &models.ApiError{Code: 500, Message: "There was an error unmarshalling raw_cert_bytes"}
	}
	csr_response.NebulaCert = *crt.Copy()
	return csr_response, nil
}

// GetCACerts retrieves the CA certificates from the NEST service
func GetCACerts() error {
	client := setupTLSClient()
	if client == nil {
		return errors.New("error in reading nest certificate")
	}
	resp, err := client.Get("https://" + Nest_service_ip + ":" + Nest_service_port + "/cacerts")
	if err != nil {
		return err
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	//var response []cert.NebulaCertificate
	var response []byte
	var error_response *models.ApiError
	switch {
	case resp.StatusCode == 200:

		// unmarshal the response into a slice of NebulaCertificates
		err = json.Unmarshal(b, &response)
		if err != nil {
			return err
		}
		// write the certificates to the ca.crt file
		os.WriteFile(Conf_folder+"ca.crt", response, 0600)
		/*
			file, err := os.OpenFile("ca.crt", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
			if err != nil {
				return err
			}
			for _, nc := range response {
				b, err := nc.MarshalToPEM()
				if err != nil {
					return err
				}
				file.Write(b)
			}
			file.Close()
		*/

	case resp.StatusCode >= 400:

		// if json.Unmarshal(b, error_response) == nil { // previous version
		if json.Unmarshal(b, &error_response) == nil {
			if error_response != nil {
				return error_response
			}
		} else {
			return errors.New("issues unmarshalling json error response: " + string(b))
		}
	}
	return nil
}

// The Sign function returns an HMAC of the given hostname
func sign(hostname string, rand []byte) []byte {
	key, err := os.ReadFile("./config/hmac.key")
	if err != nil {
		return nil
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(hostname))

	return mac.Sum(rand)
}

// send a request to the NEST service to authorize the host
// this will send the ncsr POST request to initialize the ncsr_status file server side and will then create the ncsr_status file client side with the status "Pending"
func AuthorizeHost() error {
	var auth models.NestAuth

	auth.Hostname = Hostname
	// read the secret from the file
	b, err := os.ReadFile(Nebula_auth)
	if err != nil {
		return err
	}

	//fmt.Println("Secret: ", string(b))

	// decode the secret from hex
	//auth.Secret, err = hex.DecodeString(string(b)) // previous code
	auth.Secret, err = hex.DecodeString(string(bytes.TrimSpace(b)))
	if err != nil {
		return err
	}

	//auth.Secret = sign("nest_client_lin_64", nil)

	authBytes, _ := json.Marshal(auth)

	client := setupTLSClient()
	if client == nil {
		return errors.New("error in reading nest certificate")
	}
	resp, err := client.Post("https://"+Nest_service_ip+":"+Nest_service_port+"/ncsr", "application/json", bytes.NewReader(authBytes)) // bytes.NewReader(authBytes) is the body of the request

	if err != nil {
		return err
	}

	b, err = io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	var error_response *models.ApiError

	switch {
	// if the response status code is 201, create the ncsr_status file and write "Pending" to the ncsr_status file
	case resp.StatusCode == 201:
		os.WriteFile(Conf_folder+"ncsr_status", []byte("Pending"), 0600)
	case resp.StatusCode >= 400:
		if json.Unmarshal(b, &error_response) == nil {
			if error_response.Code != 0 {
				return error_response
			} else {
				fmt.Println("There was an error unmarshalling the error response: " + err.Error())
				return err
			}
		} else {
			return errors.New("issues unmarshalling json error response: " + string(b))
		}
	}

	return nil
}

func createNESTRequest(url string, csr_bytes []byte) (*http.Request, error) {
	b, err := os.ReadFile(Nebula_auth)
	if err != nil {
		return nil, err
	}
	//secret, err := hex.DecodeString(string(b))
	secret, err := hex.DecodeString(string(bytes.TrimSpace(b)))
	if err != nil {
		return nil, err
	}
	otp, err := totp.GenerateCodeCustom(base32.StdEncoding.EncodeToString(secret), time.Now(), totp.ValidateOpts{Digits: 10, Period: 2, Skew: 1, Algorithm: otp.AlgorithmSHA256})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(csr_bytes))
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("NESToken", otp)
	return req, nil
}

func Enroll() error {

	var csr models.NebulaCsr

	start := time.Now()
	defer func() {
		fmt.Printf("Enroll function took %s\n", time.Since(start))
	}()

	csr.Hostname = Hostname
	// generate the key pair
	out, err := exec.Command(Bin_folder+"nebula-cert"+File_extension, "keygen", "-out-pub", Conf_folder+csr.Hostname+".pub", "-out-key", Conf_folder+csr.Hostname+".key").CombinedOutput()
	if err != nil {
		fmt.Println("There was an error creating the Nebula key pair: " + string(out))
		return err
	}

	// read the public key and remove the file
	b, err := os.ReadFile(Conf_folder + csr.Hostname + ".pub")
	if err != nil {
		return err
	}
	os.Remove(Conf_folder + csr.Hostname + ".pub")
	csr.PublicKey, _, err = cert.UnmarshalX25519PublicKey(b)
	if err != nil {
		return err
	}

	// create the certificate signing request
	raw_csr := models.RawNebulaCsr{
		Hostname:  csr.Hostname,
		PublicKey: csr.PublicKey,
	}
	csr_bytes, err := protojson.Marshal(&raw_csr)
	if err != nil {
		return err
	}

	// create the client to send the request
	client := setupTLSClient()
	if client == nil {
		return errors.New("error in reading nest certificate")
	}

	// send the enrollment request to the NEST service
	req, err := createNESTRequest("https://"+Nest_service_ip+":"+Nest_service_port+"/ncsr/"+Hostname+"/enroll", csr_bytes)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}

	// read the response
	b, err = io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	var error_response *models.ApiError
	var csr_response *models.NebulaCsrResponse
	switch {
	case resp.StatusCode == 200:
		csr_response, err = getCSRResponse(b)
		if err != nil {
			return err
		}

		// create the nebula_conf folder if it does not exist
		Nebula_conf_folder = csr_response.NebulaPath
		// write the path to the nebula_conf.txt file, why?????
		os.WriteFile("nebula_conf.txt", []byte(Nebula_conf_folder), 0666)
		absPath, err := filepath.Abs(Nebula_conf_folder)
		if err != nil {
			return err
		}

		if err := os.MkdirAll(absPath, 0700); err != nil {
			return err
		}

		// move the private key to the file
		if err := os.Rename(Conf_folder+csr.Hostname+".key", Nebula_conf_folder+csr.Hostname+".key"); err != nil {
			return err
		}

		// move the ca.crt file to the nebula_conf folder
		if err := os.Rename(Conf_folder+"ca.crt", Nebula_conf_folder+"ca.crt"); err != nil {
			return err
		}

		// write the config to the file
		os.WriteFile(Nebula_conf_folder+"config.yml", csr_response.NebulaConf, 0600)

		// write the host certificate to the file
		b, err = csr_response.NebulaCert.MarshalToPEM()
		if err != nil {
			return err
		}
		os.WriteFile(Nebula_conf_folder+Hostname+".crt", b, 0600)

		// start the timer for reenrollment
		//reenrollAfter(csr_response.NebulaCert) // previous version
		reenrollAfter(&csr_response.NebulaCert)

	// if the response status code is greater than 400, unmarshal the error response and return it
	case resp.StatusCode >= 400:
		//if json.Unmarshal(b, &error_response) == nil { // previous version
		if err := json.Unmarshal(b, &error_response); err != nil {
			if error_response.Code != 0 {
				return error_response
			} else {
				fmt.Println("There was an error unmarshalling the error response: " + err.Error())
				return err
			}
		} else {
			return errors.New("issues unmarshalling json error response: " + string(b))
		}
	}
	return nil
}

// Send the Enroll request to the NEST service with the server keygen flag set to true, this will return buth the certificate and the related private key
// NO pub key is recived if i'm not wrong, is this ok?
func ServerKeygen() error {
	var csr models.NebulaCsr

	start := time.Now()
	defer func() {
		fmt.Printf("Enroll function took %s\n", time.Since(start))
	}()

	// generate the certificate signing request
	csr.Hostname = Hostname
	csr.ServerKeygen = true
	raw_csr := models.RawNebulaCsr{
		Hostname:     csr.Hostname,
		ServerKeygen: &csr.ServerKeygen,
	}
	csr_bytes, err := protojson.Marshal(&raw_csr)
	if err != nil {
		return err
	}

	// create the client to send the request
	client := setupTLSClient()
	if client == nil {
		return errors.New("error in reading nest certificate")
	}

	// send the request to the NEST service asking to generate the key
	req, err := createNESTRequest("https://"+Nest_service_ip+":"+Nest_service_port+"/ncsr/"+Hostname+"/serverkeygen", csr_bytes)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}

	// read the response
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	var error_response *models.ApiError
	var csr_response *models.NebulaCsrResponse
	switch {
	case resp.StatusCode == 200:
		csr_response, err = getCSRResponse(b)
		if err != nil {
			return err
		}

		// create the nebula_conf folder if it does not exist
		Nebula_conf_folder = csr_response.NebulaPath
		// write the path to the nebula_conf.txt file, why?????
		os.WriteFile("nebula_conf.txt", []byte(Nebula_conf_folder), 0666)
		absPath, err := filepath.Abs(Nebula_conf_folder)
		if err != nil {
			return err
		}

		if err := os.MkdirAll(absPath, 0700); err != nil {
			return err
		}

		// write the private key to the file
		key := cert.MarshalX25519PrivateKey(csr_response.NebulaPrivateKey)
		if err := os.WriteFile(Nebula_conf_folder+csr.Hostname+".key", key, 0600); err != nil {
			if os.IsNotExist(err) {
				file, err := os.Create(Nebula_conf_folder + csr.Hostname + ".key")
				if err != nil {
					return err
				}
				defer file.Close()
				if _, err := file.Write(key); err != nil {
					return err
				}
			} else {
				return err
			}
		}

		// move the ca.crt file to the nebula_conf folder
		if err := os.Rename(Conf_folder+"ca.crt", Nebula_conf_folder+"ca.crt"); err != nil {
			return err
		}

		// write the config to the file
		os.WriteFile(Nebula_conf_folder+"config.yml", csr_response.NebulaConf, 0600)

		// write the host certificate to the file
		b, err = csr_response.NebulaCert.MarshalToPEM()
		if err != nil {
			return err
		}
		os.WriteFile(Nebula_conf_folder+Hostname+".crt", b, 0600)

		// start the timer for reenrollment
		// reenrollAfter(csr_response.NebulaCert) // previous version
		reenrollAfter(&csr_response.NebulaCert)

	// if the response status code is greater than 400, unmarshal the error response and return it
	case resp.StatusCode >= 400:
		// if json.Unmarshal(b, &error_response) == nil { // previous version
		if err := json.Unmarshal(b, &error_response); err != nil {
			if error_response.Code != 0 {
				return error_response
			} else {
				fmt.Println("There was an error unmarshalling the error response: " + err.Error())
				return err
			}
		} else {
			return errors.New("issues unmarshalling json error response: " + string(b))
		}
	}
	return nil
}

func Reenroll() {
	var csr models.NebulaCsr

	csr.Hostname = Hostname
	if Rekey { // if the rekey flag is set to true, generate a new key pair
		csr.Rekey = Rekey
		// check if the nebula-cert file exists, if it does not exist, set the server keygen flag to true
		if _, err := os.Stat(Bin_folder + "nebula-cert"); err != nil {
			csr.ServerKeygen = true
		} else {
			// remove the old key pair and generate a new one
			os.Remove(Nebula_conf_folder + Hostname + ".key")
			out, err := exec.Command(Bin_folder+"nebula-cert"+File_extension, "keygen", "-out-pub", Nebula_conf_folder+csr.Hostname+".pub", "-out-key", Nebula_conf_folder+Hostname+".key").CombinedOutput()
			if err != nil {
				fmt.Println("There was an error creating the Nebula key pair: " + string(out))
				Enroll_chan <- -1 * time.Second
				return
			}

			b, err := os.ReadFile(Nebula_conf_folder + csr.Hostname + ".pub")
			if err != nil {
				Enroll_chan <- -1 * time.Second // somewhere someone will know that an error occurred
				return
			}
			// remove the public key file
			os.Remove(Nebula_conf_folder + csr.Hostname + ".pub")
			csr.PublicKey, _, err = cert.UnmarshalX25519PublicKey(b)
			if err != nil {
				Enroll_chan <- -1 * time.Second // somewhere someone will know that an error occurred
				return
			}
		}
	}

	// create the certificate signing request
	raw_csr := models.RawNebulaCsr{
		Hostname:     csr.Hostname,
		PublicKey:    csr.PublicKey,
		Rekey:        &csr.Rekey,
		ServerKeygen: &csr.ServerKeygen,
	}
	csr_bytes, err := protojson.Marshal(&raw_csr)
	if err != nil {
		Enroll_chan <- -1 * time.Second
		return
	}

	// create the client to send the request
	client := setupTLSClient()
	if client == nil {
		Enroll_chan <- -1 * time.Second
		return
	}

	// send the reenroll request to the NEST service, if the csr.ServerKeygen is set to true the reenroll request will also return a new key
	req, err := createNESTRequest("https://"+Nest_service_ip+":"+Nest_service_port+"/ncsr/"+Hostname+"/reenroll", csr_bytes)
	if err != nil {
		Enroll_chan <- -1 * time.Second
		return
	}
	resp, err := client.Do(req)
	if err != nil {
		Enroll_chan <- -1 * time.Second
		return
	}

	// read the response
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		Enroll_chan <- -1 * time.Second
		return
	}
	var error_response *models.ApiError
	var csr_response *models.NebulaCsrResponse
	switch {
	case resp.StatusCode == 200:
		// unmarshal the response into a NebulaCsrResponse struct
		csr_response, err = getCSRResponse(b)
		if err != nil {
			Enroll_chan <- -1 * time.Second
			return
		}

		// recreate the nebula_conf folder if the path has changed for some reason
		if Nebula_conf_folder != csr_response.NebulaPath {
			os.RemoveAll(Nebula_conf_folder)
			Nebula_conf_folder = csr_response.NebulaPath
			absPath, _ := filepath.Abs(Nebula_conf_folder)
			os.MkdirAll(absPath, 0700)
		}

		// write the new config to the file
		os.WriteFile(Nebula_conf_folder+"config.yml", csr_response.NebulaConf, 0600)

		// if the server keygen flag is set to true, write the new private key to the file, if false you should have regenerated the key previously if needed
		if csr.ServerKeygen {
			key := cert.MarshalX25519PrivateKey(csr_response.NebulaPrivateKey)
			os.WriteFile(Nebula_conf_folder+csr.Hostname+".key", key, 0600)
		}

		// write the new host certificate to the file
		b, err = csr_response.NebulaCert.MarshalToPEM()
		if err != nil {
			Enroll_chan <- -1 * time.Second
			return
		}
		os.WriteFile(Nebula_conf_folder+Hostname+".crt", b, 0600)

		// start the timer for reenrollment
		// reenrollAfter(csr_response.NebulaCert) // previous version
		reenrollAfter(&csr_response.NebulaCert)

	// if the response status code is greater than 400, unmarshal the error response and return it
	case resp.StatusCode >= 400:
		// if json.Unmarshal(b, error_response) != nil { // previous version
		if json.Unmarshal(b, &error_response) == nil {
			if error_response != nil {
				Enroll_chan <- -1 * time.Second
				return
			}
		}
	}
}
