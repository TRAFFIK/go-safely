package client

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ProtonMail/gopenpgp/v2/helper"
	"github.com/dustin/go-humanize"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	succeed         = "SUCCESS"
	sendSafelyApi   = "https://sendsafely.com/api/v2.0"
	maxFileSize     = 2621440 // 2.5 MBs
	URLsPerRequest  = 25
	APIKeyHeader    = "ss-api-key"
	TimestampHeader = "ss-request-timestamp"
	SignatureHeader = "ss-request-signature"
)

type Options struct {
	APIKey    string
	APISecret string
	Host      string
}

type Client struct {
	clientMu sync.Mutex // clientMu protects the client during calls that modify it.

	options Options
	client  *http.Client // HTTP client used to communicate with the API.

	BaseURL *url.URL
}

type ResponseFields struct {
	Response string `json:"response"`
	Message  string `json:"message,omitempty"`
}

type ResponseChecker interface {
	Success() error
}

type UploadUrlsResponse struct {
	UploadUrls []struct {
		Part int    `json:"part,omitempty"`
		URL  string `json:"url,omitempty"`
	} `json:"uploadUrls,omitempty"`
	ResponseFields
}

func (r *UploadUrlsResponse) Success() error {
	if r.Response != succeed {
		return fmt.Errorf("UploadUrlsResponseException: %v", r.Message)
	}
	return nil
}

type DownloadUrlsResponse struct {
	DownloadUrls []struct {
		Part int    `json:"part"`
		URL  string `json:"url"`
	} `json:"downloadUrls"`
	ResponseFields
}

func (r *DownloadUrlsResponse) Success() error {
	if r.Response != succeed {
		return fmt.Errorf("DownloadUrlsResponseException: %v", r.Message)
	}
	return nil
}

type PublicKeysResponse struct {
	PublicKeys []struct {
		ID  string `json:"id,omitempty"`
		Key string `json:"key,omitempty"`
	} `json:"publicKeys,omitempty"`
	ResponseFields
}

func (r *PublicKeysResponse) Success() error {
	if r.Response != succeed {
		return fmt.Errorf("PublicKeysResponseException: %v", r.Message)
	}
	return nil
}

type AddRecipientResponse struct {
	ApprovalRequired   bool   `json:"approvalRequired,omitempty"`
	CheckForPublicKeys bool   `json:"checkForPublicKeys,omitempty"`
	RecipientID        string `json:"recipientId,omitempty"`
	Email              string `json:"email,omitempty"`
	Phonenumbers       []struct {
		CountryCode         int  `json:"countryCode,omitempty"`
		Phonenumber         int  `json:"phonenumber,omitempty"`
		WasUsedMostRecently bool `json:"wasUsedMostRecently,omitempty"`
	} `json:"phonenumbers,omitempty"`
	FullName       string `json:"fullName,omitempty"`
	SmsAuth        bool   `json:"smsAuth,omitempty"`
	IsPackageOwner bool   `json:"isPackageOwner,omitempty"`
	RoleName       string `json:"roleName,omitempty"`
	ResponseFields
}

func (r *AddRecipientResponse) Success() error {
	if r.Response != succeed {
		return fmt.Errorf("AddRecipientResponseException: %v", r.Message)
	}
	return nil
}

type UploadKeycodesResponse struct {
	ResponseFields
}

func (r *UploadKeycodesResponse) Success() error {
	if r.Response != succeed {
		return fmt.Errorf("UploadKeycodesResponseException: %v", r.Message)
	}
	return nil
}

type RequestBuildingError string

func (e *RequestBuildingError) Error() string {
	return fmt.Sprintf("request building error: %s", string(*e))
}

type RequestMakingError string

func (e *RequestMakingError) Error() string {
	return fmt.Sprintf("request error: %s", string(*e))
}

type writeCounter struct {
	Current  uint64
	Total    uint64
	Progress func(uint64, uint64)
}

func (wc *writeCounter) Write(p []byte) (int, error) {
	n := len(p)
	wc.Current += uint64(n)
	wc.Progress(wc.Current, wc.Total)
	return n, nil
}

func ProgressPrintBytes(current uint64, total uint64) {
	fmt.Printf("\r%s", strings.Repeat(" ", 35))
	fmt.Printf("\r%s/%s", humanize.Bytes(current), humanize.Bytes(total))
}

func ProgressNone(current uint64, total uint64) {}

func NewClient(options Options) (*Client, error) {
	baseEndpoint, err := url.ParseRequestURI(options.Host)
	if err != nil {
		return nil, err
	}
	// ensure the baseURL contains a trailing slash so that all paths are preserved in later calls
	if !strings.HasSuffix(baseEndpoint.Path, "/") {
		baseEndpoint.Path += "/"
	}
	return &Client{
		options: options,
		client:  &http.Client{},
		BaseURL: baseEndpoint,
	}, nil
}

func (c *Client) NewRequest(ctx context.Context, method, URL string, data interface{}) (*http.Request, error) {
	rel, err := url.Parse(URL)
	if err != nil {
		return nil, err
	}

	rel.Path = strings.TrimLeft(rel.Path, "/")
	u := c.BaseURL.ResolveReference(rel)

	//Marshal Payload
	var buf io.ReadWriter
	if data != nil {
		buf = new(bytes.Buffer)
		err = json.NewEncoder(buf).Encode(data)
		if err != nil {
			return nil, err
		}
	}

	//Convert the body to []byte for header signing
	var bufReader io.Reader
	var dataBytes []byte
	if buf != nil {
		dataBytes, err = io.ReadAll(buf)
		if err != nil {
			return nil, err
		}
	}
	bufReader = io.NopCloser(bytes.NewBuffer(dataBytes))

	req, err := http.NewRequestWithContext(ctx, method, u.String(), bufReader)
	if err != nil {
		return nil, err
	}

	c.addAuthHeaders(req, u.Path, dataBytes, time.Now())
	req.Header.Set("Content-Type", "application/json")

	return req, nil
}

func (c *Client) Do(req *http.Request) (*http.Response, error) {
	httpResp, err := c.client.Do(req)

	return httpResp, err
}

// TODO: remove return value, cause we use response pointers
// sendRequest Path: api/client.go
func (c *Client) sendRequest(method, URL string, body interface{}, responseStruct ResponseChecker) (*ResponseChecker, error) {

	request, err := c.NewRequest(context.Background(), method, URL, body)
	if err != nil {
		return nil, fmt.Errorf("building request to %s failed: %s", URL, err)
	}

	response, err := c.Do(request)
	if err != nil {
		return nil, fmt.Errorf("sending to %s request failed: %s", URL, err)
	}

	b, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response from %s failed: %s", URL, err)
	}

	//fmt.Println(string(b))
	err = json.Unmarshal(b, responseStruct)
	if err != nil {
		return nil, fmt.Errorf("unmarshaling response from %s failed: %s", URL, err)
	}

	if err = responseStruct.Success(); err != nil {
		return &responseStruct, err
	}
	return &responseStruct, nil
}

func getDateString(date time.Time) string {
	return date.Format("2006-01-02T15:04:05-0700")
}

func (c *Client) addAuthHeaders(req *http.Request, URL string, data []byte, date time.Time) {
	dateString := getDateString(date)

	signature := createSignature(c.options.APIKey, c.options.APISecret, URL, data, dateString)
	req.Header.Add(APIKeyHeader, c.options.APIKey)
	req.Header.Add(TimestampHeader, dateString)
	req.Header.Add(SignatureHeader, signature)
}

func computeHmac256(secret string, data []byte) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write(data)
	return strings.ToUpper(hex.EncodeToString(h.Sum(nil)))
}

func createSignature(APIKey string, APISecret string, URL string, data []byte, dateString string) string {
	content := APIKey + URL + dateString
	data = bytes.TrimRight(data, "\n")
	hash := computeHmac256(APISecret, append([]byte(content), data...))
	return hash
}

// AddRecipient	adds a recipient to this package
// https://bump.sh/doc/sendsafely-rest-api/operation/operation-addrecipient
func (c *Client) AddRecipient(p *Package, email string) (*AddRecipientResponse, error) {
	URL := fmt.Sprintf("/package/%s/recipient", p.ID)

	body := make(map[string]interface{})
	body["email"] = email

	responseData := &AddRecipientResponse{}
	_, err := c.sendRequest(http.MethodPut, URL, body, responseData)
	if err != nil {
		return nil, err
	}
	return responseData, nil
}

// def update_recipient_phone_number(self, recipient_id, phone, country_code="US"):
// """
// Update a recipient phone number
// :param recipient_id: The id of the recipient
// :param phone: The desired phone number, string in the form "(123) 456-7890"
// :param country_code: The country code
// :return:
// """
// sendsafely = self.sendsafely
// endpoint = "/package/" + self.package_id + "/recipient/" + recipient_id
// url = sendsafely.BASE_URL + endpoint
// body = {'phoneNumber': phone, 'countrycode': country_code}
// headers = make_headers(sendsafely.API_SECRET, sendsafely.API_KEY, endpoint, request_body=json.dumps(body))
// try:
// response = requests.post(url, headers=headers, json=body).json()
// except Exception as e:
// raise UpdateRecipientFailedException(details=str(e))
// if response["response"] != "SUCCESS":
// raise UpdateRecipientFailedException(details=response["message"])
// return response
func (*Client) UpdateRecipient() {

}

// def encrypt_and_upload_message(self, message):
// """
// Adds a message to this package
// :param message: the message to add
// :return: the JSON response
// """
// self._block_operation_without_keycode()
// try:
// encrypted_message = _encrypt_message(message_to_encrypt=message, server_secret=self.server_secret,
// client_secret=self.client_secret)
// body = {'message': encrypted_message}
// endpoint = "/package/" + self.package_id + "/message/"
// url = self.sendsafely.BASE_URL + endpoint
// headers = make_headers(self.sendsafely.API_SECRET, self.sendsafely.API_KEY, endpoint, request_body=json.dumps(body))
// response = requests.put(url, headers=headers, json=body).json()
// except Exception as e:
// raise UploadMessageException(details=str(e))
// if response["response"] != "SUCCESS":
// raise UploadMessageException(details=response["message"])
// return response
func (*Client) EncryptAndUploadMessage() {

}

// PublicKeys get the public keys for authorised account
// https://bump.sh/doc/sendsafely-rest-api/operation/operation-get-package-parameter-public-keys
func (c *Client) PublicKeys(p *Package) (*PublicKeysResponse, error) {
	URL := fmt.Sprintf("/package/%s/public-keys", p.ID)

	response := &PublicKeysResponse{}
	_, err := c.sendRequest(http.MethodGet, URL, nil, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

// UploadKeycodes Get public keys available for the account
func (c *Client) UploadKeycodes(p *Package, publicKeys *PublicKeysResponse, clientSecret string) ([]string, error) {
	var uploaded []string
	for _, key := range publicKeys.PublicKeys {
		encryptedKeycode, err := encryptKeycode(clientSecret, key.Key)
		if err != nil {
			return uploaded, err
		}

		URL := fmt.Sprintf("/package/%s/link/%s/", p.ID, key.ID)

		body := make(map[string]interface{})
		body["keycode"] = encryptedKeycode

		response := &UploadKeycodesResponse{}
		_, err = c.sendRequest(http.MethodPut, URL, body, response)
		if err != nil {
			return uploaded, err
		}

		uploaded = append(uploaded, key.ID)
	}
	return uploaded, nil
}

//def _encrypt_keycode(keycode, public_key):
//"""
//Encrypts a keycode with a public key
//:param keycode
//:param public_key
//:return: The encrypted keycode
//"""
//key_pair = pgpy.PGPKey.from_blob(public_key)[0]
//
//# https://github.com/SecurityInnovation/PGPy/issues/257
//# PGPY requires KeyFlags.EncryptCommunications and KeyFlags.EncryptStorage for public key to encrypt
//# which we are not setting in our current APIs
//# the following code injects the require attributes to the public key signature to bypass PGPY check
//user = None
//if key_pair.is_primary:
//if user is not None:
//user = key_pair.get_uid(user)
//else:
//user = next(iter(key_pair.userids))
//
//if user is not None:
//user.selfsig._signature.subpackets.addnew('KeyFlags', hashed=True,
//flags={KeyFlags.EncryptCommunications,
//KeyFlags.EncryptStorage})
//user.selfsig._signature.subpackets['h_KeyFlags'] = user.selfsig._signature.subpackets['KeyFlags'][0]
//user.selfsig._signature.subpackets.addnew('PreferredHashAlgorithms', hashed=True, flags=[HashAlgorithm.SHA256])
//user.selfsig._signature.subpackets.addnew('PreferredSymmetricAlgorithms', hashed=True,
//flags=[SymmetricKeyAlgorithm.AES256])
//user.selfsig._signature.subpackets.addnew('PreferredCompressionAlgorithms', hashed=True,
//flags=[CompressionAlgorithm.Uncompressed])
//
//message = PGPMessage.new(keycode, compression=CompressionAlgorithm.Uncompressed,
//cipher=SymmetricKeyAlgorithm.AES256,
//hash=HashAlgorithm.SHA256)
//cipher_message = key_pair.encrypt(message)
//return str(cipher_message)

func encryptKeycode(keycode string, publicKey string) (string, error) {
	//entityList, err := openpgp.ReadKeyRing(bytes.NewBufferString(publicKey))

	encrypted, err := helper.EncryptMessageArmored(publicKey, keycode)
	if err != nil {
		return "", err
	}
	fmt.Println(encrypted)

	return encrypted, nil
}

// def get_package_message(self):
// """
// :returns: The decrypted message
// """
// self._block_operation_without_keycode()
// try:
// packageChecksum = _calculate_package_checksum(package_code=self.package_code, keycode=self.client_secret)
// endpoint = '/package/' + self.package_id + '/message/' + packageChecksum["packageChecksum"]
// url = self.sendsafely.BASE_URL + endpoint
// headers = make_headers(self.sendsafely.API_SECRET, self.sendsafely.API_KEY, endpoint)
// response = requests.get(url, headers=headers).json()
// message = _decrypt_message(response["message"], server_secret=self.server_secret,
// client_secret=self.client_secret)
// return message
// except Exception as e:
// raise GetPackageMessageException(details=str(e))
func (*Client) GetPackageMessage() {

}

// def delete_file_from_package(self, file_id):
// """
// Deletes the file with the specified id from the package with the specified ID
// """
// endpoint = "/package/" + self.package_id + "/file/" + file_id
// url = self.sendsafely.BASE_URL + endpoint
// headers = make_headers(self.sendsafely.API_SECRET, self.sendsafely.API_KEY, endpoint)
// try:
// response = requests.delete(url=url, headers=headers).json()
// except Exception as e:
// raise DeleteFileException(details=e)
// if response["response"] != "SUCCESS":
// raise DeleteFileException(details=response["message"])
// return response
func DeleteFileFromPackage() {

}

// GetFileInformation retrieves information about a file
// https://bump.sh/doc/sendsafely-rest-api/operation/operation-get-package-parameter-directory-parameter-file-parameter
func (c *Client) GetFileInformation(packageId, fileId, directoryId string) (*GetFileInformationResponse, error) {
	URL := fmt.Sprintf("/package/%s/file/%s", packageId, fileId)
	if directoryId != "" {
		URL = fmt.Sprintf("/package/%s/directory/%s/file/%s", packageId, fileId, directoryId)
	}

	response := &GetFileInformationResponse{}
	_, err := c.sendRequest(http.MethodGet, URL, nil, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (c *Client) DownloadAndDecryptFile(p PackageInfoResponse, fileID, directoryID, downloadDirectory, fileName, clientSecret string) error {
	fileInfo, err := c.GetFileInformation(p.PackageID, fileID, directoryID)
	if err != nil {
		return err
	}

	//Open file for writing
	if fileName == "" {
		fileName = fileInfo.File.FileName
	}
	filePath := downloadDirectory + "/" + fileName
	fh, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return err
	}
	defer fh.Close()

	counter := &writeCounter{
		0,
		fileInfo.FileSizeInt(),
		func(u uint64, u2 uint64) {
		},
	}
	for start := 1; start <= fileInfo.TotalFileParts(); start += URLsPerRequest {
		parts, err := c.GetDownloadUrls(p, fileID, directoryID, clientSecret, start, start+URLsPerRequest)
		if err != nil {
			return err
		}

		for _, part := range parts.DownloadUrls {
			b, err := c.downloadFilePart(part.URL)
			if err != nil {
				return err
			}

			decrypted, err := decryptFilePart(b, p.ServerSecret, clientSecret)
			if err != nil {
				return err
			}

			_, err = io.Copy(fh, io.TeeReader(bytes.NewReader(decrypted), counter))
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// GetUploadUrls Retrieves the S3 upload URLs from SendSafely
// https://bump.sh/doc/sendsafely-rest-api/operation/operation-getuploadurls
func (c *Client) GetUploadUrls(p *Package, fileID string, part int) (*UploadUrlsResponse, error) {
	if part > URLsPerRequest {
		return nil, errors.New("part must be less than " + strconv.Itoa(URLsPerRequest))
	}
	URL := fmt.Sprintf("/package/%s/file/%s/upload-urls/", p.ID, fileID)

	body := make(map[string]string, 1)
	body["part"] = strconv.Itoa(part)

	response := &UploadUrlsResponse{}
	_, err := c.sendRequest(http.MethodPost, URL, body, response)
	if err != nil {
		return nil, err
	}
	return response, nil
}

// GetDownloadUrls
// https://bump.sh/doc/sendsafely-rest-api/operation/operation-post-package-parameter-file-parameter-download-urls
func (c *Client) GetDownloadUrls(p PackageInfoResponse, fileId, directoryId, clientSecret string, start, end int) (*DownloadUrlsResponse, error) {
	URL := fmt.Sprintf("/package/%s/file/%s/download-urls", p.PackageID, fileId)
	if directoryId != "" {
		URL = fmt.Sprintf("/package/%s/directory/%s/file/%s/download-urls", p.PackageID, fileId, directoryId)
	}

	body := make(map[string]interface{})
	body["packageChecksum"] = packageChecksum(p.PackageCode, clientSecret)
	body["startSegment"] = start
	body["endSegment"] = end

	response := &DownloadUrlsResponse{}
	_, err := c.sendRequest(http.MethodPost, URL, body, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}
