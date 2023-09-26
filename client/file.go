package client

import (
	"bytes"
	"fmt"
	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/dustin/go-humanize"
	"github.com/pkg/errors"
	"io"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
)

type File struct {
	FileID          string `json:"fileId"`
	FileName        string `json:"fileName"`
	FileSize        string `json:"fileSize"`
	Parts           int    `json:"parts"`
	FileUploaded    string `json:"fileUploaded"`
	FileUploadedStr string `json:"fileUploadedStr"`
	FileVersion     string `json:"fileVersion"`
	CreatedByEmail  string `json:"createdByEmail"`
}

type AddFileResponse struct {
	ResponseFields
	FileID          string `json:"fileId,omitempty"`
	FileName        string `json:"fileName,omitempty"`
	FileSize        string `json:"fileSize,omitempty"`
	Parts           int    `json:"parts,omitempty"`
	FileUploaded    string `json:"fileUploaded,omitempty"`
	FileUploadedStr string `json:"fileUploadedStr,omitempty"`
	FileVersion     string `json:"fileVersion,omitempty"`
	CreatedByEmail  string `json:"createdByEmail,omitempty"`
	FileState       string `json:"fileState,omitempty"`
}

func (r *AddFileResponse) Success() error {
	if r.Response != succeed {
		return fmt.Errorf("AddFileResponseException: %v", r.Message)
	}
	return nil
}

type FileUploadResponse struct {
	ResponseFields
}

type UpdateFileCompletionStatusResponse struct {
	ResponseFields
}

func (r *UpdateFileCompletionStatusResponse) Success() error {
	if r.Response != succeed {
		return fmt.Errorf("UpdateFileCompletionStatusResponseException: %v", r.Message)
	}
	return nil
}

type GetFileInformationResponse struct {
	File struct {
		FileID         string `json:"fileId"`
		FileName       string `json:"fileName"`
		FileSize       string `json:"fileSize"`
		CreatedByEmail string `json:"createdByEmail"`
		Uploaded       string `json:"uploaded"`
		UploadedStr    string `json:"uploadedStr"`
		FileParts      int    `json:"fileParts"`
		OldVersions    []struct {
			FileID         string `json:"fileId"`
			FileName       string `json:"fileName"`
			FileSize       string `json:"fileSize"`
			CreatedByEmail string `json:"createdByEmail"`
			Uploaded       string `json:"uploaded"`
			UploadedStr    string `json:"uploadedStr"`
			FileParts      int    `json:"fileParts"`
		} `json:"oldVersions"`
	} `json:"file"`
	ResponseFields
}

func (r *GetFileInformationResponse) Success() error {
	if r.Response != succeed {
		return fmt.Errorf("GetFileInformationResponseException: %v", r.Message)
	}
	return nil
}

func (f *GetFileInformationResponse) FileSizeInt() uint64 {
	i, _ := strconv.Atoi(f.File.FileSize)
	return uint64(i)
}

func (f *GetFileInformationResponse) FileSizeHumanize() string {
	return humanize.Bytes(f.FileSizeInt())
}

func (f *GetFileInformationResponse) TotalFileParts() int {
	return f.File.FileParts
}

// EncryptAndUploadFile Adds the passed file to the package with the specified ID
// If bigger than 2621440 Bytes, split the file by 2621440 Bytes and set parts according to the amount of splits
func (c *Client) EncryptAndUploadFile(p *Package, filePath string, clientSecret string) (*FileUploadResponse, error) {
	var result FileUploadResponse
	if clientSecret == "" {
		return nil, fmt.Errorf("clientSecret cant be empty. Should be random 256-bit alphanumeric string")
	}

	// TODO Throw an exception when 107.4Gb limit exceeded

	// TODO Check that key code exists - self._block_operation_without_keycode()

	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	fileInfo, err := file.Stat()
	if err != nil {
		return nil, err
	}

	filesize := fileInfo.Size()
	numParts := calculateParts(filesize)

	addFile, err := c.AddFile(p, filePath)
	if err != nil {
		return nil, err
	}

	fileId := addFile.FileID

	fmt.Println("FILES UPLOADED")
	partsUploaded := 0
	for part := 1; part <= numParts; {
		uploadUrlsResponse, err := c.GetUploadUrls(p, fileId, part)
		if err != nil {
			return nil, err
		}
		fmt.Println("UPLOADE URLS")

		for _, part := range uploadUrlsResponse.UploadUrls {
			chunkSize := maxFileSize
			if filesize < maxFileSize {
				chunkSize = int(filesize)
			} else if unprocessed := int(filesize - int64(partsUploaded*maxFileSize)); unprocessed > 0 && unprocessed < maxFileSize {
				chunkSize = unprocessed
			}

			chunk := make([]byte, chunkSize)
			_, err := file.Read(chunk)
			if err != nil {
				return nil, err
			}

			encryptedBytes, err := encryptFilePart(chunk, p.ServerSecret, clientSecret)
			if err != nil {
				return nil, err
			}

			err = UploadToS3(encryptedBytes, part.URL)
			if err != nil {
				return nil, err
			}

			//if progressInstance == nil {
			//	progressInstance = NewProgress()
			//}
			//calculateProgress(fileId, progress, numParts, progressInstance)
			partsUploaded++
		}
		part += 25
	}

	fmt.Println("CHUNKS UPLADED")

	_, err = c.UpdateFileCompletionStatus(p, fileId, true)
	if err != nil {
		return nil, err
	}

	//response["fileId"] = fileId
	return &result, nil

}

// AddFile Adds the passed file to the package with the specified ID
// If bigger than 2.5 MBs, split the file by 2.5 MBs and set parts according to the amount of splits
// https://bump.sh/doc/sendsafely-rest-api/operation/operation-createfile
func (c *Client) AddFile(p *Package, filePath string) (*AddFileResponse, error) {
	URL := fmt.Sprintf("/package/%s/file", p.ID)
	filename := filepath.Base(filePath)

	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	fileInfo, err := file.Stat()
	if err != nil {
		return nil, err
	}

	filesize := fileInfo.Size()

	parts := calculateParts(filesize)

	body := make(map[string]interface{})
	body["filename"] = filename
	body["parts"] = parts
	body["filesize"] = filesize

	// TODO: WTF directoryID ?
	//if directoryID != "" {
	//	body["directoryId"] = directoryID
	//}

	responseData := &AddFileResponse{}
	_, err = c.sendRequest(http.MethodPut, URL, body, responseData)
	if err != nil {
		return nil, err
	}

	return responseData, nil
}

func calculateParts(filesize int64) int {
	if filesize > (maxFileSize / 4) {
		return 1 + int(math.Ceil(float64(filesize-(maxFileSize/4))/float64(maxFileSize)))
	}
	return 1
}

// TODO: switch to io.Readers
// encryptFilePart encrypts a part of a file with symmetric encryption
func encryptFilePart(data []byte, serverSecret string, clientSecret string) ([]byte, error) {
	var pgpMessage *crypto.PGPMessage
	var err error
	var message = crypto.NewPlainMessageFromFile(data, "", uint32(crypto.GetUnixTime()))

	passphrase := serverSecret + clientSecret
	pgpMessage, err = crypto.EncryptMessageWithPassword(message, []byte(passphrase))

	if err != nil {
		return []byte{}, errors.Wrap(err, "gopenpgp: unable to encrypt message with password")
	}

	return pgpMessage.Data, nil
}

// decryptFilePart decrypts a part of a file with symmetric encryption
func decryptFilePart(data []byte, serverSecret string, clientSecret string) ([]byte, error) {
	passphrase := serverSecret + clientSecret

	message := crypto.NewPGPMessage(data)
	m, err := crypto.DecryptMessageWithPassword(message, []byte(passphrase))
	if err != nil {
		return nil, err
	}

	return m.Data, nil
}

// UploadToS3 Uploads the file to the specified URL
func UploadToS3(data []byte, URL string) error {
	buf := bytes.NewBuffer(data)

	request, err := http.NewRequest(http.MethodPut, URL, buf)
	if err != nil {
		return err
	}

	client := &http.Client{}
	resp, err := client.Do(request)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	fmt.Println(resp)
	return nil
}

// UpdateFileCompletionStatus Sets the file upload status as complete, the server will verify if all segments have been uploaded
// https://bump.sh/doc/sendsafely-rest-api/operation/operation-uploadcomplete
func (c *Client) UpdateFileCompletionStatus(p *Package, ID string, complete bool) (*UpdateFileCompletionStatusResponse, error) {
	URL := fmt.Sprintf("/package/%s/file/%s/upload-complete", p.ID, ID)

	body := make(map[string]interface{})
	body["complete"] = complete

	response := &UpdateFileCompletionStatusResponse{}
	_, err := c.sendRequest(http.MethodPost, URL, body, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

// TODO: switch to use Client
func (c *Client) downloadFilePart(URL string) ([]byte, error) {
	response, err := http.Get(URL)
	if err != nil {
		return []byte{}, err
	}

	defer response.Body.Close()
	b, err := io.ReadAll(response.Body)
	if err != nil {
		return []byte{}, err
	}

	return b, nil
}
