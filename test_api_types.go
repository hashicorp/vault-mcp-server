package main

import (
	"fmt"

	"github.com/hashicorp/vault/api"
)

func main() {
	// This is just to check the types available in the API
	var authMounts map[string]*api.AuthMount
	authMounts = make(map[string]*api.AuthMount)

	// Create a sample auth mount to check its fields
	authMount := &api.AuthMount{}
	authMounts["test/"] = authMount

	fmt.Printf("AuthMount type: %T\n", authMount)
	fmt.Printf("AuthMount fields available\n")
}
