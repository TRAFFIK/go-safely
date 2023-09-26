package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"golang.org/x/crypto/openpgp"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"
)

var (
	// testMux is the HTTP request multiplexer used with the test server.
	testMux *http.ServeMux

	// testClient is the Jira client being tested.
	testClient *Client

	// testServer is a test HTTP server used to provide mock API responses.
	testServer *httptest.Server
)

func setup() {
	// Test server
	testMux = http.NewServeMux()
	testServer = httptest.NewServer(testMux)

	options := Options{
		APIKey:    "1234asdf",
		APISecret: "asdf1234",
		Host:      testServer.URL,
	}
	testClient, _ = NewClient(options)
}

// teardown closes the test HTTP server.
func teardown() {
	testServer.Close()
}

func TestEncryptKeycode(t *testing.T) {
	keyCode := "1234567890"

	publicKey, err := generatePubKey()
	if err != nil {
		t.Error(err)
	}
	fmt.Println(publicKey)

	encrypted, err := encryptKeycode(keyCode, publicKey)
	if err != nil {
		t.Error(err)
	}

	fmt.Println(encrypted)
}

func generatePubKey() (string, error) {
	var e *openpgp.Entity
	e, err := openpgp.NewEntity("Test User", "test", "test@example.com", nil)
	if err != nil {
		return "", err
	}

	// Add more identities here if you wish

	// Sign all the identities
	for _, id := range e.Identities {
		err := id.SelfSignature.SignUserId(id.UserId.Id, e.PrimaryKey, e.PrivateKey, nil)
		if err != nil {
			return "", err
		}
	}

	b := new(bytes.Buffer)
	//w, err := armor.Encode(b, openpgp.PublicKeyType, nil)
	//if err != nil {
	//	return "", err
	//}
	//defer w.Close()
	e.Serialize(b)

	return b.String(), nil
}

func TestNewClientError(t *testing.T) {
	options := Options{
		APIKey:    "",
		APISecret: "",
		Host:      "wrong-one",
	}

	c, err := NewClient(options)
	if err == nil {
		t.Error("Expected an error. Got none")
	}
	if c != nil {
		t.Errorf("Expected no client. Got %+v", c)
	}
}

func TestGetDateString(t *testing.T) {
	dateString := "2019-01-14 22:24"
	date, err := time.Parse("2006-01-02 15:04", dateString)

	if err != nil {
		t.Error("Expected no error. Got " + err.Error())
	}

	result := getDateString(date)

	fmt.Println(result)
	if result != "2019-01-14T22:24:00+0000" {
		t.Error("Expected date string to be 2019-01-14T22:24:00+0000. Got " + result)
	}
}

func TestClient(t *testing.T) {
	setup()
	defer teardown()

	testMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		m := http.MethodGet
		if m != r.Method {
			t.Errorf("Request method = %v, want %v", r.Method, m)
		}
	})

	req, _ := testClient.NewRequest(context.Background(), http.MethodGet, "/", nil)
	res, _ := testClient.Do(req)
	_, err := io.ReadAll(res.Body)

	if err != nil {
		t.Errorf("Error on parsing HTTP Response = %v", err.Error())
	} else if res.StatusCode != 200 {
		t.Errorf("Response code = %v, want %v", res.StatusCode, 200)
	}
}

type Payload struct {
	VDR string `json:"vdr"`
}

func TestNewRequest(t *testing.T) {
	setup()
	defer teardown()

	want := make(map[string]interface{})
	want["vdr"] = "false"

	req, err := testClient.NewRequest(context.Background(), http.MethodGet, "/", want)
	if err != nil {
		t.Errorf("Error on creating HTTP Reuqest = %v", err.Error())
	}

	body, err := io.ReadAll(req.Body)
	if err != nil {
		t.Error("Expected no error. Got " + err.Error())
	}

	bodyMap := make(map[string]interface{})
	err = json.Unmarshal(body, &bodyMap)
	if err != nil {
		t.Error("Expected no error. Got " + err.Error())
	}

	if !reflect.DeepEqual(bodyMap, want) {
		t.Errorf("Response body = %v, want %v", bodyMap, want)
	}
}
