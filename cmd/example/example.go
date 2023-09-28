package main

import (
	"fmt"
	"github.com/TRAFFIK/go-safely/client"
	"log"
	"os"
)

func upload() {
	options := client.Options{
		APIKey:    os.Getenv("SS_API_KEY"),
		APISecret: os.Getenv("SS_API_KEY_SECRET"),
		Host:      os.Getenv("SS_API_HOST"),
	}
	clientSecret := "321dd33"

	sendSafely, err := client.NewClient(options)
	if err != nil {
		log.Fatal(err)
	}

	resp, err := sendSafely.CreatPackage()
	if err != nil {
		log.Fatal(err)
	}

	pack := client.NewPackage(resp)

	_, err = sendSafely.AddRecipient(pack, "example@mail.com")
	if err != nil {
		log.Fatal(err)
	}

	filePath := "file.txt"
	_, err = sendSafely.EncryptAndUploadFile(pack, filePath, clientSecret)
	if err != nil {
		log.Fatal(err)
	}

	r, err := sendSafely.Finalize(pack, clientSecret)
	if err != nil {
		log.Fatal(err)
	}

	link, err := pack.DownloadLink(r, clientSecret)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(link)
}

func download() {
	options := client.Options{
		APIKey:    os.Getenv("SS_API_KEY"),
		APISecret: os.Getenv("SS_API_KEY_SECRET"),
		Host:      os.Getenv("SS_API_HOST"),
	}
	clientSecret := "321dd33"
	sampleURL := os.Getenv("SAMPLE_URL")

	sendSafely, err := client.NewClient(options)
	if err != nil {
		log.Fatal(err)
	}

	u, err := sendSafely.User()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Printf("Logged in as %s (%s)\n", u.FirstName, u.Email)

	pm, err := client.PackageMetadataFromURL(sampleURL)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	p, err := sendSafely.PackageInfo(pm.PackageCode)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Printf("Package Sender: %s\n", p.PackageSender)
	fmt.Printf("Package Files:\n")
	for i, f := range p.Files {
		fp := "/tmp/" + f.FileName

		fmt.Printf("%d: %s (%s)\n", i, f.FileName, f.FileSize)
		fmt.Printf("Downloading file to %s\n", fp)
		err = sendSafely.DownloadAndDecryptFile(*p, f.FileID, "", "/tmp", f.FileName, clientSecret)
		if err != nil {
			fmt.Println(err)
			continue
		}
		fmt.Printf("Downloading complete!\n")
	}
}
