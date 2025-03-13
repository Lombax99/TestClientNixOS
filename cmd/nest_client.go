package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	nest_client "github.com/securityresearchlab/nebula-est/nest_client/pkg/logic"
	"github.com/securityresearchlab/nebula-est/nest_service/pkg/models"
)

// stops the nebula service in windows OS
func uninstall_nebula() {
	fmt.Println("Terminating nebula service...")
	exec.Command(nest_client.Bin_folder+"nebula"+nest_client.File_extension, "-service", "stop").Run()
	fmt.Println("Uninstalling nebula service...")
	exec.Command(nest_client.Bin_folder+"nebula"+nest_client.File_extension, "-service", "uninstall").Run()
}

func setupNebula(nebula_log *os.File) (*exec.Cmd, error) {
	// check if the nebula binary is present and set the correct permissions if needed
	_, err := os.Stat(nest_client.Bin_folder + "nebula" + nest_client.File_extension)
	if err != nil {
		fmt.Printf("%s doesn't exist. Cannot proceed. Please provide the nebula bin to the service before starting it\nExiting...", nest_client.Bin_folder+"nebula"+nest_client.File_extension)
		return nil, err
	}
	os.Chmod(nest_client.Bin_folder+"nebula"+nest_client.File_extension, 0700)

	// create the command based on the current OS
	var cmd *exec.Cmd // declare the cmd variable to be used later for executing the nebula binary
	if runtime.GOOS == "windows" {
		exec.Command(nest_client.Bin_folder+"nebula"+nest_client.File_extension, "-service", "install", "-config", nest_client.Nebula_conf_folder+"config.yml").Run()
		cmd = exec.Command(nest_client.Bin_folder+"nebula"+nest_client.File_extension, "-service", "start")
		cmd.Stdout = nebula_log
		cmd.Stderr = nebula_log
	} else {
		cmd = exec.Command(nest_client.Bin_folder+"nebula"+nest_client.File_extension, "-config", nest_client.Nebula_conf_folder+"config.yml")
		cmd.Stdout = nebula_log
		cmd.Stderr = nebula_log
	}
	cmd.Start()
	/*time.Sleep(3 * time.Second)	// this commented block is used to check if the nebula interface is up and running

	interfaces, err := net.Interfaces()

	if err != nil {
		fmt.Printf("Could'nt check information about host interfaces\n")
		return nil, err
	}

	var found bool = false
	for _, i := range interfaces {
		if strings.Contains(strings.ToLower(i.Name), "nebula") {
			found = true
			break
		}
	}

	if found {
		return cmd, nil
	}
	return nil, errors.New("could not setup a nebula tunnel")*/
	return cmd, nil
}

// this function will check if the nebula interface is up and running, it is not used in the current implementation
/*func checkNebulaInterface() error {
	interfaces, err := net.Interfaces()

	if err != nil {
		fmt.Printf("Could'nt check information about host interfaces\n")
		return err
	}

	var found bool = false
	for _, i := range interfaces {
		if strings.Contains(strings.ToLower(i.Name), "nebula") {
			found = true
			break
		}
	}

	if found {
		return nil
	}
	return errors.New("could not setup a nebula tunnel")
}*/

func main() {
	/* Read and set value from environment variables (no default values are given), it is expected to find the following variables:
	- NEST_SERVICE_IP: IP address of the NEST service
	- NEST_SERVICE_PORT: Port of the NEST service
	- NEST_CERT:
	- BIN_FOLDER: Folder where the nebula binary is located
	- NEBULA_AUTH: Authorization token for the NEST client, how should this be generated? It should end with "secret.hmac". What is Conf_folder?
	- HOSTNAME: Hostname of the client, if not set it will be the hostname of the machine as defined by the os
	- REKEY: Boolean value to determine if the client should do sometihng or not, I need to studie it more...
	*/
	if val, ok := os.LookupEnv("NEST_SERVICE_IP"); ok {
		nest_client.Nest_service_ip = val
	}
	if val, ok := os.LookupEnv("NEST_SERVICE_PORT"); ok {
		nest_client.Nest_service_port = val
	}
	if val, ok := os.LookupEnv("NEST_CERT"); ok {
		nest_client.Nest_certificate = val
	}
	if val, ok := os.LookupEnv("BIN_FOLDER"); ok {
		nest_client.Bin_folder = val
	}
	if val, ok := os.LookupEnv("NEBULA_AUTH"); ok {
		nest_client.Nebula_auth = val
		nest_client.Conf_folder = strings.TrimSuffix(val, "secret.hmac")
	}
	if val, ok := os.LookupEnv("HOSTNAME"); ok {
		nest_client.Hostname = val
	}
	if val, ok := os.LookupEnv("REKEY"); ok {
		nest_client.Rekey, _ = strconv.ParseBool(val)
	}
	fmt.Println("NEST client: starting setup")

	// check if the NEST service certificate is present
	if _, err := os.Stat(nest_client.Nest_certificate); err != nil {
		fmt.Printf("Cannot find NEST service certificate. Please provide the NEST certificate or CA certificate before starting nest_client\n")
		os.Exit(1)
	}
	// set the file extension if the code is running on windows
	if runtime.GOOS == "windows" {
		nest_client.File_extension = ".exe"
	}
	// check if the nebula binary is present
	if _, err := os.Stat(nest_client.Bin_folder + "nebula" + nest_client.File_extension); err != nil {
		fmt.Printf("Cannot find nebula binary. Please provide the nebula binary before starting nest_client\n")
		os.Exit(2)
	}
	// check if the authorization token is present and has the correct permissions, if not changes the permissions accordingly
	info, err := os.Stat(nest_client.Nebula_auth)
	if err != nil {
		fmt.Printf("Cannot find nest_client authorization token. Please provide the authorization token before starting nest_client\n")
		os.Exit(3)
	}
	if info.Mode()&0600 != 0 {
		os.Chmod(nest_client.Nebula_auth, 0600)
	}
	// check if the hostname is present, if not set it to the hostname of the machine
	if len(nest_client.Hostname) == 0 {
		hostname, err := os.Hostname()
		if err != nil {
			fmt.Printf("Cannot load client's hostname from environment. Please provide the hostname or set it in the os before starting nest_client\n")
			os.Exit(4)
		}
		nest_client.Hostname = hostname
	}
	// check if the ncsr_status file is present in the conf folder, if not get the CA certificates and authorize the host
	// first time the application starts this file will most likely not exist
	if _, err := os.Stat(nest_client.Conf_folder + "ncsr_status"); os.IsNotExist(err) { // if the file does not exist enters the block
		// send a request to the NEST service to get the CA certificates and save it in conf_folder/ca.crt
		if err := nest_client.GetCACerts(); err != nil {
			fmt.Printf("There was an error getting the NEST client Nebula Network CAs: %v\n", err.Error())
			os.Exit(5)
		}
		// send a request to the NEST service to authorize the host, basically send the ncsr POST request to initialize the ncsr_status file
		if err := nest_client.AuthorizeHost(); err != nil {
			fmt.Printf("There was an error authorizing the nest client: %v\n", err.Error())
			os.Exit(6)
		}
	}

	fmt.Println("NEST client: setup finished")
	//todo add error channel

	// check if the ncsr_status file is pending, if it is generate the keys and send an enrollment request
	// the file was generated in the nest_client.AuthorizeHost() function
	// normally it should be syncronized with the server but what appens if it's not? can i break the system?
	b, _ := os.ReadFile(nest_client.Conf_folder + "ncsr_status")
	if isPending, _ := regexp.Match(string(models.PENDING), b); isPending {
		// check if the nebula-cert file is NOT present, if it isn't the private key generation is left to the server to do
		if _, err := os.Stat(nest_client.Bin_folder + "nebula-cert" + nest_client.File_extension); err != nil {
			err := nest_client.ServerKeygen()
			if err != nil {
				fmt.Printf("There was an error in the enrollment request: %v\n", err)
				os.Exit(10)
			}
		} else {
			err := nest_client.Enroll()
			if err != nil {
				fmt.Printf("There was an error in the enrollment request: %v\n", err)
				os.Exit(10)
			}
		}
		fmt.Println("NEST client: enrollment successfull. Writing conf files and keys to " + nest_client.Nebula_conf_folder) // nest_client.Nebula_conf_folder is created in the nest_client.Enroll() function or nest_client.ServerKeygen()
	} else {
		// if the ncsr_status file is not pending, reenroll the client
		// read the nebula_conf.txt file, this contains the location of the nebula configuration folder, saved during nest_client.Enroll() or nest_client.ServerKeygen()
		neb_conf, err := os.ReadFile("nebula_conf.txt")
		if err != nil {
			fmt.Printf("Could not read nebula configuration location: %v\n", err)
			os.Exit(12)
		}
		// set the nebula configuration folder to the one saved in the nebula_conf.txt file
		nest_client.Nebula_conf_folder = string(neb_conf)
		// start the reenrollment process
		nest_client.Reenroll()
	}

	// open the nebula log file
	nebula_log, err := os.OpenFile(nest_client.Nebula_conf_folder+nest_client.Hostname+"_nebula.log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		fmt.Printf("There was an error creating nebula log file: %v\n", err)
		os.Exit(8)
	}
	defer nebula_log.Close()

	// start the nebula tunnel
	cmd, err := setupNebula(nebula_log)
	if err != nil {
		fmt.Printf("There was an error setting up the Nebula tunnel: %v\n", err)
		if runtime.GOOS == "windows" {
			uninstall_nebula()
		}
		os.Exit(7)
	}

	/*if err = checkNebulaInterface(); err != nil {
		fmt.Printf("There was an error setting up the Nebula tunnel: %v\n", err)
		uninstall_nebula()
		os.Exit(7)
	}*/

	// if the code is running on windows, setup a Go Routine to catch the interrupt (and similar) signal and uninstall the nebula service
	// This is used for ensuring that resources are properly released and services are correctly stopped when the program is interrupted or terminated.
	if runtime.GOOS == "windows" {
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)
		go func() {
			for sig := range c {
				fmt.Println("Caught signal: " + sig.String())
				uninstall_nebula()
			}
		}()
	}

	// this is the main loop of the program, it will check if there is a duration in the enroll channel and if there is it will reenroll the client
	for {
		select {
		case duration := <-nest_client.Enroll_chan:
			// handle errors in the enrollment process
			if duration.Hours() < 0 {
				fmt.Println("There was an error in the enrollment process")
				uninstall_nebula() // this run even in linux os, should it?
				os.Exit(9)
			}

			// schedule the re-enrollment process
			fmt.Println("NEST client: Scheduling re-enrollment in: " + duration.String())
			time.AfterFunc(duration, nest_client.Reenroll)

			// sleep for the duration +1 sec to ensure the re-enrollment process is completed correctly and then restart the nebula service
			time.Sleep(duration + 1*time.Second)
			fmt.Println("Restarting nebula after certificate renewal")
			if runtime.GOOS == "windows" {
				cmd := exec.Command(nest_client.Bin_folder+"nebula"+nest_client.File_extension, "-service", "restart")
				cmd.Stdout = os.Stdout
				cmd.Stderr = os.Stdout
				cmd.Start()
			} else {
				cmd.Process.Signal(syscall.SIGHUP) // SIGHUP signal is used to reload the nebula service configuration
				/*
				 * SIGHUP usually nitify terminal closing event but for daemon it doesn't make sense, because deamons are detached from their terminal.
				 * So the system will never send this signal to them.
				 * It is common practice for daemons to use it for another meaning, typically reloading the daemon's configuration.
				 * This is not a rule, just kind of a convention.
				 */
			}
			/*if runtime.GOOS == "windows" {
				cmd.Process = nil
				for {
					if _, err := net.InterfaceByName("nebula"); err != nil {
						if err = cmd.Start(); err != nil {
							fmt.Println("Could not restart nebula: " + err.Error())
						}
						break
					}
				}
			}*/
		default:
			continue
		}
	}

}
