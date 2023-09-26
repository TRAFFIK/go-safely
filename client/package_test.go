package client

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestNewPackage(t *testing.T) {
	resp := PackageCreateResponse{
		Package:        Package{},
		ResponseFields: ResponseFields{},
	}
	resp.ID = "1"

	p := NewPackage(&resp)
	p.ID = "2"

	assert.Equal(t, "2", p.ID)
	assert.Equal(t, "1", resp.ID)

	resp.ID = "3"
	assert.Equal(t, "3", resp.ID)
}

func TestPackageMetadataFromURL(t *testing.T) {
	type args struct {
		u string
	}
	tests := []struct {
		name    string
		args    args
		want    PackageMetadata
		wantErr assert.ErrorAssertionFunc
	}{
		{
			"valid",
			args{"https://app.sendsafely.com/api/receive/?thread=ABCD-EFGH&packageCode=123gg123#keyCode=321dd33"},
			PackageMetadata{
				Thread:      "ABCD-EFGH",
				PackageCode: "123gg123",
				KeyCode:     "321dd33",
			},
			assert.NoError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := PackageMetadataFromURL(tt.args.u)

			if !tt.wantErr(t, err, fmt.Sprintf("PackageMetadataFromURL(%v)", tt.args.u)) {
				return
			}
			assert.Equalf(t, tt.want, got, "PackageMetadataFromURL(%v)", tt.args.u)
		})
	}
}
