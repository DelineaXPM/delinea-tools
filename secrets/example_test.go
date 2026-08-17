package secrets_test

import (
	"context"
	"fmt"
	"log"

	"github.com/DelineaXPM/delinea-tools/secrets"
)

func ExampleParseMapping() {
	m, err := secrets.ParseMapping(`DB_PASS=password@\ci\database\prod`)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(m.EnvName, m.Field, m.Path)
	// Output: DB_PASS password \ci\database\prod
}

// exampleFetcher stands in for the live vault; a real program builds the
// client with secrets.New and connection settings instead.
type exampleFetcher struct{}

func (exampleFetcher) Secret(_ context.Context, id int) (*secrets.Secret, error) {
	return &secrets.Secret{ID: id, Fields: []secrets.SecretField{
		{FieldName: "username", Slug: "username", ItemValue: "svc"},
		{FieldName: "password", Slug: "password", ItemValue: "s3cr3t"},
	}}, nil
}

func (exampleFetcher) SecretByPath(context.Context, string) (*secrets.Secret, error) {
	return nil, fmt.Errorf("unused")
}

func ExampleClient_Resolve() {
	client := secrets.NewWithFetcher(exampleFetcher{})
	vars, err := client.Resolve(context.Background(), []secrets.Mapping{
		{EnvName: "DB_USER", SecretID: 128, Field: "username"},
		{EnvName: "DB_PASS", SecretID: 128, Field: "password"},
	})
	if err != nil {
		log.Fatal(err)
	}
	for _, v := range vars {
		fmt.Println(v.Name, len(v.Value))
	}
	// Output:
	// DB_USER 3
	// DB_PASS 6
}

func ExampleClient_Verify() {
	client := secrets.NewWithFetcher(exampleFetcher{})
	results, err := client.Verify(context.Background(), []secrets.Mapping{
		{EnvName: "DB_PASS", SecretID: 128, Field: "password"},
		{EnvName: "MISSING", SecretID: 128, Field: "no-such-field"},
	})
	if err != nil {
		log.Fatal(err)
	}
	for _, r := range results {
		if r.Err != nil {
			fmt.Println(r.Mapping.EnvName, "failed")
			continue
		}
		for _, f := range r.Fields {
			fmt.Println(f.Name, f.Bytes)
		}
	}
	// Output:
	// DB_PASS 6
	// MISSING failed
}
