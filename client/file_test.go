package client

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
)

func TestEncryptFilePart(t *testing.T) {
	data := []byte("test")
	serverSecret := "server"
	clientSecret := "client"

	encrypted, err := encryptFilePart(data, serverSecret, clientSecret)

	fmt.Println(string(encrypted))
	assert.NoError(t, err)
	assert.Equal(t, 1, 1)
}

func TestTemp(t *testing.T) {
	str := "12345"
	b := []byte(str)
	tmp := fmt.Sprintf("%v", b)
	b = []byte(tmp)
	//base64.Encoding{}
	fmt.Printf("%x", str)
	fmt.Printf("%q\n", "string")
	assert.Equal(t, 1, 1)
}

func TestBin(t *testing.T) {
	buf := new(bytes.Buffer)
	var data = []interface{}{
		uint16(61374),
		int8(-54),
		uint8(254),
	}
	for _, v := range data {
		err := binary.Write(buf, binary.LittleEndian, v)
		if err != nil {
			fmt.Println("binary.Write failed:", err)
		}
	}
	fmt.Printf("%x", buf.Bytes())
}

type MyStruct struct {
	Field1 int
	Field2 string
}

func (s *MyStruct) MarshalBinary() ([]byte, error) {
	// Encode the struct fields into a byte slice using binary encoding
	buf := make([]byte, 4+len(s.Field2))
	binary.LittleEndian.PutUint32(buf[:4], uint32(s.Field1))
	copy(buf[4:], []byte(s.Field2))

	return buf, nil
}

func TestBinary(t *testing.T) {
	// Create an instance of MyStruct
	s := MyStruct{
		Field1: 123,
		Field2: "hello",
	}

	// Encode the struct into a byte slice using MarshalBinary()
	encoded, err := s.MarshalBinary()
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(encoded) // prints [0x7b 0x00 0x00 0x00 0x68 0x65 0x6c 0x6c 0x6f]
}

func TestEncryptDecryptFilePart(t *testing.T) {
	type args struct {
		data         []byte
		serverSecret string
		clientSecret string
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr assert.ErrorAssertionFunc
	}{
		{
			"valid",
			args{
				data:         []byte("test"),
				serverSecret: "123",
				clientSecret: "456",
			},
			[]byte("test"),
			assert.NoError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encrypted, err := encryptFilePart(tt.args.data, tt.args.serverSecret, tt.args.clientSecret)
			if !tt.wantErr(t, err, fmt.Sprintf("encryptFilePart(%v, %v, %v)", tt.args.data, tt.args.serverSecret, tt.args.clientSecret)) {
				return
			}

			got, err := decryptFilePart(encrypted, tt.args.serverSecret, tt.args.clientSecret)
			if !tt.wantErr(t, err, fmt.Sprintf("decryptFilePart(%v, %v, %v)", tt.args.data, tt.args.serverSecret, tt.args.clientSecret)) {
				return
			}
			assert.Equalf(t, tt.want, got, "encryptFilePart(%v, %v, %v)", tt.args.data, tt.args.serverSecret, tt.args.clientSecret)
		})
	}
}

func TestClient_EncryptAndUploadFile(t *testing.T) {
	p := &Package{
		ID: "12",
	}
	serverS3 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/upload-part/1" {
			t.Errorf("Expected to request '/upload-part/1', got: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer serverS3.Close()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var respJSON []byte
		var err error
		switch r.URL.Path {
		case "/package/12/file":
			respJSON, err = json.Marshal(AddFileResponse{
				FileID: "321",
				ResponseFields: ResponseFields{
					Response: succeed,
				},
			})
		case "/package/12/file/321/upload-urls/":
			respJSON, err = json.Marshal(UploadUrlsResponse{
				UploadUrls: []UploadUrl{
					{URL: fmt.Sprintf("%s/upload-part/1", serverS3.URL), Part: 1},
				},
				ResponseFields: ResponseFields{
					Response: succeed,
				},
			})
		case "/package/12/file/321/upload-complete":
			respJSON, err = json.Marshal(UpdateFileCompletionStatusResponse{
				ResponseFields: ResponseFields{
					Response: succeed,
				},
			})
		default:
			t.Errorf("Expected to request '/fixedvalue', got: %s", r.URL.Path)
		}

		w.WriteHeader(http.StatusOK)
		if err != nil {
			t.Error("Can't marshal response object" + err.Error())
		}
		w.Write(respJSON)
	}))
	baseEndpoint, err := url.ParseRequestURI(server.URL)
	if err != nil {
		t.Error("Expected no error. Got " + err.Error())
	}
	defer server.Close()
	c := &Client{
		client:  &http.Client{},
		BaseURL: baseEndpoint,
	}

	// Test cases
	type args struct {
		limits      limits
		packageSize int64
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr assert.ErrorAssertionFunc
	}{
		{
			"success",
			args{
				limits: limits{
					maxFileSize:    100,
					maxPackageSize: 300,
					urlsPerRequest: 25,
				},
				packageSize: 200,
			},
			[]byte("test"),
			assert.NoError,
		},
		{
			"file too big",
			args{
				limits: limits{
					maxFileSize:    50,
					maxPackageSize: 80,
					urlsPerRequest: 25,
				},
				packageSize: 100,
			},
			[]byte("test"),
			assert.Error,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			// Config client
			c.limits = tt.args.limits

			// Generate test file
			file, err := os.CreateTemp("", "testFile")
			if err != nil {
				t.Error("Expected no error. Got " + err.Error())
			}
			if err := file.Truncate(tt.args.packageSize); err != nil {
				t.Error("Expected no error. Got " + err.Error())
			}
			defer os.Remove(file.Name())

			_, err = c.EncryptAndUploadFile(p, file.Name(), "123")
			if !tt.wantErr(t, err, fmt.Sprintf("encryptAndUploadFile limits(%v,%v, %v) actual size %v", tt.args.limits.maxPackageSize, tt.args.limits.maxFileSize, tt.args.limits.urlsPerRequest, tt.args.packageSize)) {
				return
			}
		})
	}

	// Run tests
	if err != nil {
		t.Error("Expected no error. Got " + err.Error())
	}
}
