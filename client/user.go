package client

import (
	"fmt"
	"net/http"
)

type User struct {
	ID          string `json:"id"`
	Email       string `json:"email"`
	ClientKey   string `json:"clientKey"`
	FirstName   string `json:"firstName"`
	LastName    string `json:"lastName"`
	BetaUser    bool   `json:"betaUser"`
	AdminUser   bool   `json:"adminUser"`
	PublicKey   bool   `json:"publicKey"`
	PackageLife int    `json:"packageLife"`
}

type UserResponse struct {
	User
	ResponseFields
}

func (r *UserResponse) Success() error {
	if r.Response != succeed {
		return fmt.Errorf("UserResponseException: %v", r.Message)
	}
	return nil
}

func (c *Client) User() (*UserResponse, error) {
	URL := "/user/"

	ui := &UserResponse{}
	err := c.sendRequest(http.MethodGet, URL, nil, ui)
	if err != nil {
		return nil, err
	}

	return ui, nil
}
