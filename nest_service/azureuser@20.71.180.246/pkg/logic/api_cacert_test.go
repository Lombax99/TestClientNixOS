package logic

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-playground/assert/v2"
	"github.com/securityresearchlab/nebula-est/nest_service/pkg/utils"
	nest_test "github.com/securityresearchlab/nebula-est/nest_service/test"
)

// test the getCaCerts function
func TestCacerts(t *testing.T) {
	var endpoint = Service_routes[0] // cacerts endpoint
	r := nest_test.MockRouterForEndpoint(&endpoint)

	// Test success case
	utils.Ca_cert_file = "../../test/config/ca.crt"
	certs, _ := getCaCertFromFile()                                     // get the certs from the file
	reqOk, _ := http.NewRequest(endpoint.Method, endpoint.Pattern, nil) // create a request
	resp := httptest.NewRecorder()
	r.ServeHTTP(resp, reqOk)
	assert.Equal(t, http.StatusOK, resp.Code) // check if the response is OK
	certsBytes, _ := json.Marshal(certs)
	assert.Equal(t, certsBytes, resp.Body.Bytes()) // check if the response body is the same as the certs

	// Test error case
	utils.Ca_cert_file = "./"
	reqError, _ := http.NewRequest(endpoint.Method, endpoint.Pattern, nil)
	resp = httptest.NewRecorder()
	r.ServeHTTP(resp, reqError)
	assert.Equal(t, http.StatusInternalServerError, resp.Code)
}
