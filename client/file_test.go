package client

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/stretchr/testify/assert"
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

func TestOpenAndEncrypt(t *testing.T) {
	filePath := "../file.txt"
	serverSecret := "ABSEtm43123"
	clientSecret := "ATvE4331"

	file, err := os.Open(filePath)
	assert.NoError(t, err)

	defer file.Close()

	fileInfo, err := file.Stat()
	assert.NoError(t, err)

	filesize := fileInfo.Size()

	chunkSize := maxFileSize
	if filesize < maxFileSize {
		chunkSize = int(filesize)
	}

	fmt.Println(filesize)
	chunk := make([]byte, chunkSize)

	n, err := file.Read(chunk)
	fmt.Println(n)
	assert.NoError(t, err)
	fmt.Println(len(chunk))

	encrypted, err := encryptFilePart(chunk, serverSecret, clientSecret)

	fmt.Println(encrypted)
	assert.NoError(t, err)
	URL := "http://localhost:3114/ping"

	err = UploadToS3(encrypted, URL)
	assert.NoError(t, err)
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
