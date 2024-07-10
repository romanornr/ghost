package ghost

import (
	"fmt"
	"math/rand"
	"os"
	"testing"
	"time"
)

//func mustGetCredentialsFromEnv() (ghostURL, contentAPIToken, adminAPIToken string) {
//	ghostURL = os.Getenv("GHOST_URL")
//	contentAPIToken = os.Getenv("GHOST_CONTENT_API_TOKEN")
//	adminAPIToken = os.Getenv("GHOST_ADMIN_API_TOKEN")
//
//	if ghostURL == "" || contentAPIToken == "" || adminAPIToken == "" {
//		panic("GHOST_URL, GHOST_CONTENT_API_TOKEN and GHOST_ADMIN_API_TOKEN are required")
//	}
//}

func mustGetCredentialsFromEnv() (ghostURL, ghostContentAPIToken, ghostAdminAPIToken string) {
	ghostURL = os.Getenv("GHOST_URL")
	ghostContentAPIToken = os.Getenv("GHOST_CONTENT_API_TOKEN")
	ghostAdminAPIToken = os.Getenv("GHOST_ADMIN_API_TOKEN")
	if ghostURL == "" || ghostAdminAPIToken == "" || ghostContentAPIToken == "" {
		panic("GHOST_URL, GHOST_ADMIN_API_TOKEN and GHOST_CONTENT_API_TOKEN must be set in the environment")
	}
	return
}

func TestGetMembers(t *testing.T) {
	ghostURL, ghostContentAPIToken, ghostAdminAPIToken := mustGetCredentialsFromEnv()
	g := New(ghostURL, ghostContentAPIToken, ghostAdminAPIToken)

	members, err := g.AdminGetMembers()
	if err != nil {
		t.Fatalf("Error getting members: %s", err)
	}

	rand.Seed(time.Now().UnixNano())
	randomMailAddress := fmt.Sprintf("testmail-%d@gmx.de", rand.Int())
	_, err = g.AdminCreateMember(NewMember{
		Name:  "Test Member",
		Email: randomMailAddress,
	})
	if err != nil {
		t.Fatalf("Error creating member: %s", err)
	}

	// Fetch members again and compare size of lists
	membersAfterCreation, err := g.AdminGetMembers()
	if err != nil {
		t.Fatalf("Error getting members second time: %s", err)
	}
	if len(membersAfterCreation.Members) == len(members.Members) {
		t.Fatalf("Member count did not change after creation")
	}

	// Check if email matches
	found := false
	for _, member := range membersAfterCreation.Members {
		if member.Email == randomMailAddress {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("Member not found in list after creation")
	}
}

//ghostURL := "https://demo.ghost.io"
//contentAPIToken := "c1e7c4e2b5e9"
//adminAPIToken := "b1e7c4e
