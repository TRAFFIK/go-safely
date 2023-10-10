package client

import (
	"crypto/sha256"
	"fmt"
	"github.com/dchest/pbkdf2"
	"net/http"
	"net/url"
	"strings"
)

type Package struct {
	ID                 string   `json:"packageId"`
	ParentID           string   `json:"packageParentId"`
	UserName           string   `json:"packageUserName"`
	UserID             string   `json:"packageUserId"`
	UpdateTimestampStr string   `json:"packageUpdateTimestampStr"`
	State              string   `json:"packageState"`
	StateStr           string   `json:"packageStateStr"`
	StateColor         string   `json:"packageStateColor"`
	Life               int      `json:"packageLife"`
	UpdateTimestamp    string   `json:"packageUpdateTimestamp"`
	Code               string   `json:"packageCode"`
	Browser            string   `json:"packageBrowser"`
	OS                 string   `json:"packageOS"`
	HasMessage         bool     `json:"packageContainsMessage"`
	Recipients         []string `json:"recipients"`
	RecipientCount     int      `json:"recipientCount"`
	Filenames          []string `json:"filenames"`
	ContactGroups      []string `json:"contactGroups"`
	ServerSecret       string   `json:"serverSecret,omitempty"` //It's package specific TODO: investigate which requests returns it
}

type PackageCreateResponse struct {
	Package
	ResponseFields
}

func (r *PackageCreateResponse) Success() error {
	if r.Response != succeed {
		return fmt.Errorf("PackageCreateResponseException: %v", r.Message)
	}
	return nil
}

type FinalizePackageResponse struct {
	ResponseFields
	Approvers  []string `json:"approvers,omitempty"`
	Recipients []string `json:"recipients,omitempty"`
	NeedsLink  bool     `json:"needsLink,omitempty"`
	Response   string   `json:"response,omitempty"`
	Message    string   `json:"message,omitempty"`
}

func (r *FinalizePackageResponse) Success() error {
	if r.Response != succeed {
		return fmt.Errorf("FinalizePackageResponseException: %v", r.Message)
	}
	return nil
}

// PackageInfoResponse TODO: use it as a compasition of Pakage instead
type PackageInfoResponse struct {
	PackageID   string `json:"packageId"`
	PackageCode string `json:"packageCode"`
	Recipients  []struct {
		RecipientID        string        `json:"recipientId"`
		Email              string        `json:"email"`
		FullName           string        `json:"fullName"`
		NeedsApproval      bool          `json:"needsApproval"`
		RecipientCode      string        `json:"recipientCode"`
		Confirmations      []interface{} `json:"confirmations"`
		IsPackageOwner     bool          `json:"isPackageOwner"`
		CheckForPublicKeys bool          `json:"checkForPublicKeys"`
		RoleName           string        `json:"roleName"`
	} `json:"recipients"`
	ContactGroups []struct {
		ContactGroupID                  string `json:"contactGroupId"`
		ContactGroupName                string `json:"contactGroupName"`
		ContactGroupIsOrganizationGroup bool   `json:"contactGroupIsOrganizationGroup"`
		Users                           []struct {
			UserEmail string `json:"userEmail"`
			UserID    string `json:"userId"`
		} `json:"users"`
	} `json:"contactGroups"`
	Files            []File        `json:"files"`
	Directories      []interface{} `json:"directories"`
	ApproverList     []interface{} `json:"approverList"`
	NeedsApproval    bool          `json:"needsApproval"`
	State            string        `json:"state"`
	PasswordRequired bool          `json:"passwordRequired"`
	Life             int           `json:"life"`
	Label            string        `json:"label"`
	IsVDR            bool          `json:"isVDR"`
	IsArchived       bool          `json:"isArchived"`
	PackageSender    string        `json:"packageSender"`
	PackageTimestamp string        `json:"packageTimestamp"`
	RootDirectoryID  string        `json:"rootDirectoryId"`
	ResponseFields
	ServerSecret string `json:"serverSecret,omitempty"` //TODO: investigate which requests returns it
}

func (r *PackageInfoResponse) Success() error {
	if r.Response != succeed {
		return fmt.Errorf("PackageInfoResponseException: %v", r.Message)
	}
	return nil
}

func (r *PackageInfoResponse) Package() Package {
	return Package{
		ID:                 r.PackageID,
		ParentID:           "",
		UserName:           "",
		UserID:             "",
		UpdateTimestampStr: "",
		State:              "",
		StateStr:           "",
		StateColor:         "",
		Life:               0,
		UpdateTimestamp:    "",
		Code:               "",
		Browser:            "",
		OS:                 "",
		HasMessage:         false,
		Recipients:         nil,
		RecipientCount:     0,
		Filenames:          nil,
		ContactGroups:      nil,
		ServerSecret:       r.ServerSecret,
	}
}

type PackageMetadata struct {
	Thread      string
	PackageCode string
	KeyCode     string
}

func NewPackage(resp *PackageCreateResponse) *Package {
	res := resp.Package
	return &res
}

// CreatPackage Path: api/client.go
// https://bump.sh/doc/sendsafely-rest-api/operation/operation-createpackage
func (c *Client) CreatPackage() (*PackageCreateResponse, error) {
	URL := fmt.Sprint("/package/")

	body := make(map[string]interface{})
	body["vdr"] = "false"

	response := &PackageCreateResponse{}
	err := c.sendRequest(http.MethodPut, URL, body, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

// PackageInfo Get a detailed status of a given package
// https://bump.sh/doc/sendsafely-rest-api/operation/operation-getpackageinformation
func (c *Client) PackageInfo(packageId string) (*PackageInfoResponse, error) {
	URL := fmt.Sprintf("/package/%s", packageId)

	response := &PackageInfoResponse{}
	err := c.sendRequest(http.MethodGet, URL, nil, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

// def delete_package(self):
// """
// Delete this package.
// """
// try:
// response = delete_request(self.sendsafely, "/package/" + self.package_id)
// except Exception as e:
// raise DeletePackageException(details=str(e))
// if response["response"] != "SUCCESS":
// raise DeletePackageException(response["message"])
func (*Client) DeletePackage() {

}

// Finalize finalizes the package, returns a link, including the keycode
// https://bump.sh/doc/sendsafely-rest-api/operation/operation-finalizepackage
func (c *Client) Finalize(p *Package, clientSecret string) (*FinalizePackageResponse, error) {
	keys, err := c.PublicKeys(p)
	if err != nil {
		return nil, err
	}

	fmt.Println("Public keys ready")
	_, err = c.UploadKeycodes(p, keys, clientSecret)
	if err != nil {
		return nil, err
	}

	fmt.Println("Keycode uploaded")
	checksum := packageChecksum(clientSecret, p.Code)
	body := make(map[string]interface{})
	body["filename"] = checksum

	fmt.Println("packageChecksum ready")
	URL := fmt.Sprintf("/package/%s/finalize", p.ID)

	response := &FinalizePackageResponse{}
	err = c.sendRequest(http.MethodPost, URL, body, response)
	if err != nil {
		return nil, err
	}

	//keycode = "#keyCode=" + self.client_secret
	//response["message"] = response["message"] + keycode
	return response, nil
}

// Calculates the packageChecksum of a package using keycode (Client Secret) and Package Code
// Checksum is generated using PBKDF2-HMAC-SHA256 with keycode as the password, and Package Code as salt.
func packageChecksum(keyCode string, packageCode string) string {
	key := pbkdf2.WithHMAC(sha256.New, []byte(keyCode), []byte(packageCode), 1024, 64)
	key = key[:32]
	return fmt.Sprintf("%x", key)
}

func (*Package) DownloadLink(response *FinalizePackageResponse, clientSecret string) (string, error) {
	URL, err := url.ParseRequestURI(response.Message)
	if err != nil {
		return "", fmt.Errorf("InvalidDownloadLinkException: %v", err)
	}

	return fmt.Sprintf("%s#keyCode=%s", URL.String(), clientSecret), nil
}

// PackageMetadataFromURL Extracts PackageMetadata from string URL
func PackageMetadataFromURL(u string) (PackageMetadata, error) {
	var pm PackageMetadata

	v, err := url.Parse(u)
	if err != nil {
		return pm, err
	}

	q := v.Query()
	pm.PackageCode = q.Get("packageCode")
	pm.Thread = q.Get("thread")

	f := v.Fragment
	p := strings.Split(f, "=")
	if len(p) == 2 {
		if p[0] == "keyCode" {
			pm.KeyCode = p[1]
		}
	}

	if pm.PackageCode == "" || pm.Thread == "" || pm.KeyCode == "" {
		return PackageMetadata{"", "", ""}, fmt.Errorf("could not find packageCode, thread or keyCode in URL")
	}

	return pm, nil
}

func (c *Client) GetPackageFromURL(packageURL string) (*PackageInfoResponse, error) {
	var p *PackageInfoResponse

	pm, err := PackageMetadataFromURL(packageURL)
	if err != nil {
		return p, err
	}

	p, err = c.PackageInfo(pm.PackageCode)
	if err != nil {
		return p, err
	}

	return p, nil
}
