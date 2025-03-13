/*
# Nebula Enrollment over Secure Transport - OpenAPI 3.0

This is a simple Public Key Infrastructure Management Server based on the RFC7030 Enrollment over Secure Transport Protocol for a Nebula Mesh Network.
The Service accepts requests from TLS connections to create Nebula Certificates for the client (which will be authenticated by providing a secret).
The certificate creation is done either by signing client-generated Nebula Public Keys or by generating Nebula key pairs and signing the server-generated
Nebula public key and to create Nebula configuration files for the specific client. This Service acts as a Facade for the Nebula CA service
(actually signign or creating the Nebula keys) and the Nebula Config service (actually creating the nebula Config. files).

API version: 0.3.1
Contact: gianmarco.decola@studio.unibo.it
Contact: luca.lombardi12@studio.unibo.it
*/

package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/securityresearchlab/nebula-est/nest_service/pkg/logic"
	"github.com/securityresearchlab/nebula-est/nest_service/pkg/models"
	"github.com/securityresearchlab/nebula-est/nest_service/pkg/utils"
)

// getHostnames sends an http request to the nest_config service over a Nebula network to get the valid hostnames.
func getHostnames() ([]string, error) {
	var resp *http.Response
	var err error
	var error_response *models.ApiError
	// TODO: add retry limit for timeout error
	for {
		resp, err = http.Get("http://" + utils.Conf_service_ip + ":" + utils.Conf_service_port + "/hostnames")
		if err != nil {
			urlErr := err.(*url.Error)
			if urlErr.Timeout() {
				fmt.Println("NEST config is not ready, waiting and retrying in 1 second")
				time.Sleep(1 * time.Second)
				continue
			} else {
				if resp != nil {
					b, err := io.ReadAll(resp.Body)
					if err != nil {
						return nil, err
					}
					// if json.Unmarshal(b, error_response) != nil {	// previous version
					if err := json.Unmarshal(b, &error_response); err != nil {
						if error_response != nil {
							return nil, error_response
						}
					}
				}
			}
		} else {
			break
		}
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var response []string
	err = json.Unmarshal(b, &response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

/*
checkHostnamesFile checks if the file containing all the valid hostnames already exists.
If not, it creates it and populates it by sending a request to the nest_config service
*/
func checkHostnamesFile() error {
	if _, err := os.Stat(utils.Hostnames_file); err != nil {
		fmt.Printf("%s doesn't exist. Creating it and requesting the valid hostnames from Nebula conf service\n", utils.Hostnames_file)
		// Get the hostnames from the NEST Config service
		hostnames, err := getHostnames()
		if err != nil {
			fmt.Printf("There has been an error with the hostnames request: %v", err.Error())
			return err
		}

		file, err := os.OpenFile(utils.Hostnames_file, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
		if err != nil {
			fmt.Printf("Could not write to file: %v", err)
			return err
		}
		defer file.Close()

		for _, h := range hostnames {
			file.WriteString(h + "\n")
		}
	}
	return nil
}

// SetupTLS sets up the tls configuration for the nest_service server
func setupTLS() *tls.Config {
	var tls_config = tls.Config{
		MinVersion:               tls.VersionTLS12,
		MaxVersion:               tls.VersionTLS13,
		PreferServerCipherSuites: true,
		//CurvePreferences:         []tls.CurveID{tls.X25519, tls.CurveP256},
		CipherSuites: []uint16{
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		},
	}
	return &tls_config
}

/*
nest_service is a REST API server which acts a facade between NEST clients and the inner Nebula CA and configuration services.
In the main function, the proper environment is set up before starting a Gin https server rechable by the clients and an http client over a
Nebula network for authentication and confidentiality among the peers (NEST , NEST_CA and NEST_CONFIG services)
*/
func main() {
	/* Read and set value from environment variables, it is expected to find the following variables:
	- LOG_FILE: path to the log file, if not set, the default is log/nest_service.log, if the file doesn't exist, it will be created
	- SERVICE_IP: IP address where the service will listen for incoming requests, if not set, the default is localhost, see more below
	- SERVICE_PORT: Port where the service will listen for incoming requests, if not set, the default is 8080
	- HOSTNAMES_FILE: path to the file containing the valid hostnames, if not set, the default is config/hostnames. I think the hostname refers to the nodes in the Nebula network
	- CA_CERT_FILE: path to the file containing the CA certificate, if not set, the default is config/ca.crt. This is the CA certificate used to sign the client certificates
	- NEBULA_FOLDER: path to the folder containing the Nebula configuration files, if not set, the default is config/nebula/
					 This folder should contain the Nebula configuration files: nest_service.crt, nest_service.key, nest_system_ca.crt, config.yml, nest_service_nebula.log and the nebula binary
	- HMAC_KEY: path to the file containing the HMAC key, if not set, the default is config/hmac.key.
				This key is used to sign the HMACs, it can be generated with the command:  "head /dev/urandom | sha256sum > hmac.key"
				For SHA-256, a key length of at least 256 bits is recommended
	- CA_SERVICE_IP: IP address of the CA service on the Nest network, if not set, the default is 192.168.80.1
	- CA_SERVICE_PORT: Port of the CA service on the Nest network, if not set, the default is 53535
	- CONF_SERVICE_IP: IP address of the CONF service on the Nest network, if not set, the default is 192.168.80.2
	- CONF_SERVICE_PORT: Port of the CONF service on the Nest network, if not set, the default is 61616
	- NCSR_FOLDER: path to the Ncsr folder, if not set, the default is ncsr/   (is stands for Nebula Certificate Signing Request)
				   this contains the file used for the NCSR-status optimization
	- TLS_FOLDER: path to the folder containing the TLS certificates and keys, if not set, the default is config/tls/
	 			  contains the following files: nest_service-key.pem and nest_service-crt.pem
	*/

	if val, ok := os.LookupEnv("LOG_FILE"); ok {
		utils.Log_file = val
	}
	if val, ok := os.LookupEnv("SERVICE_IP"); ok {
		utils.Service_ip = val
	}
	if val, ok := os.LookupEnv("SERVICE_PORT"); ok {

		utils.Service_port = val
	}
	if val, ok := os.LookupEnv("HOSTNAMES_FILE"); ok {
		utils.Hostnames_file = val
	}
	if val, ok := os.LookupEnv("CA_CERT_FILE"); ok {
		utils.Ca_cert_file = val
	}
	if val, ok := os.LookupEnv("NEBULA_FOLDER"); ok {
		utils.Nebula_folder = val
	}
	if val, ok := os.LookupEnv("HMAC_KEY"); ok {
		utils.HMAC_key = val
	}
	if val, ok := os.LookupEnv("CA_SERVICE_IP"); ok {
		utils.Ca_service_ip = val
	}
	if val, ok := os.LookupEnv("CA_SERVICE_PORT"); ok {
		utils.Ca_service_port = val
	}
	if val, ok := os.LookupEnv("CONF_SERVICE_IP"); ok {
		utils.Conf_service_ip = val
	}
	if val, ok := os.LookupEnv("CONF_SERVICE_PORT"); ok {
		utils.Conf_service_port = val
	}
	if val, ok := os.LookupEnv("NCSR_FOLDER"); ok {
		utils.Ncsr_folder = val
	}
	if val, ok := os.LookupEnv("TLS_FOLDER"); ok {
		utils.TLS_folder = val
	}
	if val, ok := os.LookupEnv("Eidolon"); ok && val == "true" {
		utils.Eidolon = true
		println("Eidolon mode is set to true")
	} else {
		utils.Eidolon = false
		println("Eidolon mode is set to false")
	}
	fmt.Println("NEST service: starting setup")

	// Check if the necessary ./Ncsr folders exist and create them if they don't
	if _, err := os.Stat(utils.Ncsr_folder); err != nil {
		if err := os.Mkdir(utils.Ncsr_folder, 0700); err != nil {
			fmt.Printf("Couldn't create /ncsr directory: %v\n", err)
			os.Exit(4)
		}
	}

	// Check if the necessary nest_service.crt files exist in the Nebula folder
	if _, err := os.Stat(utils.Nebula_folder + "nest_service.crt"); err != nil {
		fmt.Printf("Cannot find NEST service Nebula certificate: %v\n", err)
		os.Exit(5)
	}

	// Check if the necessary nest_service.key files exist in the Nebula folder
	if _, err := os.Stat(utils.Nebula_folder + "nest_service.key"); err != nil {
		fmt.Printf("Cannot find NEST service Nebula key: %v\n", err)
		os.Exit(6)
	}

	// Check if the necessary nest_system_ca.crt files exist in the Nebula folder
	if _, err := os.Stat(utils.Nebula_folder + "nest_system_ca.crt"); err != nil {
		fmt.Printf("Cannot find NEST Nebula CA crt: %v\n", err)
		os.Exit(7)
	}

	// Check if the necessary config.yml files exist in the Nebula folder
	if _, err := os.Stat(utils.Nebula_folder + "config.yml"); err != nil {
		fmt.Printf("Cannot find NEST Nebula config: %v\n", err)
		os.Exit(8)
	}

	// Open the log file with the proper permissions, create it if it doesn't exist and truncate it to 0 if it does
	// will log errors in the /config/nebula folder instead of the default /log folder
	nebula_log, err := os.OpenFile(utils.Nebula_folder+"nest_service_nebula.log", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		fmt.Printf("There was an error creating nebula log file: %v\n", err)
		os.Exit(8)
	}
	defer nebula_log.Close() // close the log file when the main function ends

	// Start the Nebula tunnel, returns an error if the Nebula binary is not found or if it is not executable, nil otherwise
	if err := utils.SetupNebula(utils.Nebula_folder, nebula_log); err != nil {
		fmt.Printf("There was an error setting up the Nebula tunnel:%v\n", err)
		os.Exit(9)
	}

	// Check if the CA certificate file and the hostnames file exist
	// This is the GET: Cacerts request defined in the Enroll graph image
	if err := logic.CheckCaCertFile(); err != nil {
		fmt.Printf("Could not contact the CA service: %v\n", err)
		os.Exit(2)
	}

	// Check if the hostnames file exists, create it if it doesn't
	// This is the GET: GetValidHostnames request defined in the Enroll graph image
	if err := checkHostnamesFile(); err != nil {
		fmt.Printf("Could not contact the Conf service: %v\n", err)
		os.Exit(3)
	}

	// Check if the necessary TLS files exist in the TLS folder
	if _, err := os.Stat(utils.TLS_folder + "nest_service-key.pem"); err != nil {
		fmt.Printf("Cannot find NEST service TLS key\n")
		os.Exit(10)
	}
	if _, err := os.Stat(utils.TLS_folder + "nest_service-crt.pem"); err != nil {
		fmt.Printf("Cannot find NEST TLS crt\n")
		os.Exit(11)
	}

	// Check if the HMAC key file exists and has the proper permissions
	info, err := os.Stat(utils.HMAC_key)
	if err != nil {
		fmt.Printf("Cannot find HMAC key\n")
		os.Exit(12)
	}
	// If the file is not readable and writable by the owner, change the permissions to 0600, doesn't make the file executable obviously
	if !utils.IsRWOwner(info.Mode()) {
		os.Chmod(utils.HMAC_key, 0600)
	}

	// returns the tls configuration for the server
	tls_config := setupTLS()
	fmt.Println("NEST service: setup finished")

	// Create a new Gin router with the default middleware, no trsuted proxies and a custom logger with Log_file as output
	router := gin.Default()
	router.SetTrustedProxies(nil)
	utils.SetupLogger(router, utils.Log_file)

	// maps GET and POST request paths to the proper handler functions as defined in logic.Service_routes
	for _, r := range logic.Service_routes {
		switch r.Method {
		case "GET":
			router.GET(r.Pattern, r.HandlerFunc)
		case "POST":
			router.POST(r.Pattern, r.HandlerFunc)
		}
	}

	// Setup the server with the proper TLS configuration, Service IP and Service Port are by default localhost and 8080
	// setting localhost as the IP will make the server listen only on the localhost interface... which is bad... i think... or maybe Nebula will make it usable... idk
	srv := http.Server{
		Addr:      utils.Service_ip + ":" + utils.Service_port,
		Handler:   router,
		TLSConfig: tls_config,
	}

	// Start the server with the proper TLS configuration requiring the TLS key and certificate
	err = srv.ListenAndServeTLS(utils.TLS_folder+"nest_service-crt.pem", utils.TLS_folder+"nest_service-key.pem")
	if err != nil {
		fmt.Println("Error in Setting up TLS server: " + err.Error())
	}
}
