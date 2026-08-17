package api_test

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/DelineaXPM/delinea-tools/api"
)

// A Secret Server call: authenticate with the password grant and fetch one
// secret. Do returns a Response for any HTTP status; errors are reserved for
// configuration, authentication, and transport failures.
func ExampleClient_Do() {
	client, err := api.New(api.Config{
		URL:      "https://acme.secretservercloud.com",
		Username: "svc-api",
		Password: os.Getenv("SS_PASSWORD"),
	})
	if err != nil {
		log.Fatal(err)
	}
	resp, err := client.Do(context.Background(), api.Request{
		Method: http.MethodGet,
		Path:   "/api/v1/secrets/126",
	})
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Fatalf("secret fetch failed: %s", resp.Status)
	}
	io.Copy(os.Stdout, resp.Body)
}

// A Delinea Platform call routed to the tenant's Secret Server vault: the
// client-credentials grant runs against the platform, the vault broker
// discovers the vault URL, and UseVault sends the request there with the
// same bearer token.
func ExampleClient_Do_platformVault() {
	client, err := api.New(api.Config{
		URL:          "https://acme.secureplatform.io",
		ClientID:     os.Getenv("PLATFORM_CLIENT_ID"),
		ClientSecret: os.Getenv("PLATFORM_CLIENT_SECRET"),
	})
	if err != nil {
		log.Fatal(err)
	}
	resp, err := client.Do(context.Background(), api.Request{
		Method:   http.MethodGet,
		Path:     "/api/v1/secrets/4",
		UseVault: true,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	io.Copy(os.Stdout, resp.Body)
}

// A shared in-memory cache lets many short-lived Clients reuse one token
// grant per identity for the life of the process; nothing is written to
// disk, and a rotated credential invalidates its entry immediately.
func ExampleNewMemoryCache() {
	cache := api.NewMemoryCache()
	cfg := api.Config{
		URL:      "https://acme.secretservercloud.com",
		Username: "svc-api",
		Password: os.Getenv("SS_PASSWORD"),
		Cache:    cache,
	}
	for _, path := range []string{"/api/v1/users/current", "/api/v1/folders"} {
		client, err := api.New(cfg)
		if err != nil {
			log.Fatal(err)
		}
		resp, err := client.Do(context.Background(), api.Request{Method: http.MethodGet, Path: path})
		if err != nil {
			log.Fatal(err)
		}
		resp.Body.Close()
		fmt.Println(path, resp.Status)
	}
}

// Token exposes the bearer directly, for callers that make their own HTTP
// requests or hand the token to another tool.
func ExampleClient_Token() {
	client, err := api.New(api.Config{
		URL:      "https://acme.secretservercloud.com",
		Username: "svc-api",
		Password: os.Getenv("SS_PASSWORD"),
	})
	if err != nil {
		log.Fatal(err)
	}
	token, err := client.Token(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodGet, "https://acme.secretservercloud.com/api/v1/version", nil)
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	_ = req
}
