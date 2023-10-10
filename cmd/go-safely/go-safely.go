package main

import (
	"fmt"
	"github.com/spf13/cobra"
	"log"
	"os"

	gosafely "github.com/TRAFFIK/go-safely/client"
)

var (
	apiURL       = os.Getenv("SS_API_HOST")
	apiKeyID     = os.Getenv("SS_API_KEY_ID")
	apiKeySecret = os.Getenv("SS_API_KEY_SECRET")
	clientSecret = os.Getenv("SS_CLIENT_SECRET")
	client       *gosafely.Client
	ssURL        string

	rootCmd = &cobra.Command{
		Use:   "go-safely",
		Short: "go-safely is a CLI for SendSafely",
	}
	downloadCmd = &cobra.Command{
		Use:   "download",
		Short: "Download the files in a package",
		Run: func(cmd *cobra.Command, args []string) {
			checkCredentials()
			download()
		},
	}
)

func init() {
	options := gosafely.Options{
		APIKey:    os.Getenv("SS_API_KEY"),
		APISecret: os.Getenv("SS_API_KEY_SECRET"),
		Host:      os.Getenv("SS_API_HOST"),
	}

	client, _ = gosafely.NewClient(options)

	downloadCmd.Flags().StringVarP(&ssURL, "url", "u", "", "Package URL")
	downloadCmd.MarkFlagRequired("url")
	rootCmd.AddCommand(downloadCmd)
}

func main() {
	rootCmd.Execute()
}

func download() {
	sampleURL := os.Getenv("SAMPLE_URL")

	u, err := client.User()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Logged in as %s (%s)\n", u.FirstName, u.Email)

	pm, err := gosafely.PackageMetadataFromURL(sampleURL)
	if err != nil {
		log.Fatal(err)
	}

	p, err := client.PackageInfo(pm.PackageCode)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Package Sender: %s\n", p.PackageSender)
	fmt.Printf("Package Files:\n")
	for i, f := range p.Files {
		fp := "./" + f.FileName

		fmt.Printf("%d: %s (%s)\n", i, f.FileName, f.FileSize)
		fmt.Printf("Downloading file to %s\n", fp)
		err = client.DownloadAndDecryptFile(*p, f.FileID, "", "./", f.FileName, clientSecret)
		if err != nil {
			fmt.Println(err)
			continue
		}
		fmt.Printf("Downloading complete!\n")
	}
}

func checkCredentials() {
	if apiURL == "" || apiKeyID == "" || apiKeySecret == "" || clientSecret == "" {
		log.Fatal("Undefined environment vars. Please set SS_API_HOST, SS_API_KEY_ID, SS_API_KEY_SECRET and SS_CLIENT_SECRET")
	}
}
