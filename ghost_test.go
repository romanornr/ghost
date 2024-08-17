package ghost

import (
	"context"
	"fmt"
	"github.com/joho/godotenv"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"log"
	"net/http"
	"os"
	"testing"
	"time"
)

// MockHTTPClient is a mock implementation of the HTTPClient interface for testing purposes. It
// embeds the mock.Mock struct from the "github.com/stretchr/testify/mock" package, allowing
// assertions to be made on method calls and return values.
type MockHTTPClient struct {
	mock.Mock
}

type MockRoundTripper struct {
	mock.Mock
}

func (m *MockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	args := m.Called(req)
	return args.Get(0).(*http.Response), args.Error(1)
}

// GetEnvCredentials retrieves the GHOST_URL, CONTENT_API_KEY, and ADMIN_API_KEY from the environment variables.
// It loads the environment variables from the .env file using godotenv.
// If any of the environment variables is missing or empty, it panics with a specific error message.
// It returns the retrieved values for GHOST_URL, CONTENT_API_KEY, and ADMIN_API_KEY as strings.
func GetEnvCredentials() (string, string, string) {
	// read environment variables from .env file with godotenv
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Error loading .env file")
	}

	ghostURL := os.Getenv("GHOST_URL")
	contentAPIKey := os.Getenv("GHOST_CONTENT_API_TOKEN")
	adminAPIKey := os.Getenv("GHOST_ADMIN_API_TOKEN")

	fmt.Printf("GHOST_URL: %s\n", ghostURL)
	fmt.Printf("CONTENT_API_KEY: %s\n", contentAPIKey)
	fmt.Printf("ADMIN_API_KEY: %s\n", adminAPIKey)

	if ghostURL == "" || contentAPIKey == "" || adminAPIKey == "" {
		panic("Missing environment variables. Please set GHOST_URL, CONTENT_API_KEY, and ADMIN_API_KEY.")
	}

	return ghostURL, contentAPIKey, adminAPIKey
}

func (m *MockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	args := m.Called(req)

	// Extract the predefined response and error from thr function call arguments
	// We assert the first argument to be of type *http.Response and the second argument to be of type error
	// These are predefined outputs in our tests when this method is invoked
	return args.Get(0).(*http.Response), args.Error(1)
}

// TestNewClient tests the NewClient function by creating a new client and validating
// that the baseURL and httpClient are correctly set.
func TestNewClient(t *testing.T) {
	baseURL := "https://ghost.org"
	c := NewClient(baseURL).(*client)

	assert.Equal(t, baseURL, c.baseURL)
	assert.Equal(t, baseURL, c.baseURL)
	assert.NotNil(t, c.httpClient)
}

// TestWithContentAPIKey tests the function withContentAPIKey by creating a new client and
// validating that the contentAPIKey is correctly set to the provided key.
func TestWithContentAPIKey(t *testing.T) {
	c := &client{}
	key := "test-content-api-key"
	WithContentAPIKey(key)(c)

	assert.Equal(t, key, c.contentAPIKey)
}

func TestWithAdminAPIKey(t *testing.T) {
	c := &client{}
	key := "test-admin-api-key"
	WithAdminAPIKey(key)(c)

	assert.Equal(t, key, c.adminAPIKey)
}

// TestGetJWTToken tests the getJWTToken method of the client struct by calling it
// and checking that the returned token is not empty and no error occurred.
// It also tests the caching functionality by setting a future expiration time,
// calling getJWTToken again, and asserting that the cached token is returned.
// No additional assertions are made regarding the validity of the token or the
// correctness of the expiration time calculation.
func TestGetJWTToken(t *testing.T) {
	c := &client{
		adminAPIKey: "test:1234567890abcdef",
	}

	ctx := context.Background()
	token, err := c.getJWTToken(ctx)

	assert.NoError(t, err)
	assert.NotEmpty(t, token)

	// Test caching
	c.jwtExpiresAt = time.Now().Add(1 * time.Minute)
	cachedToken, err := c.getJWTToken(ctx)
	assert.NoError(t, err)
	assert.Equal(t, token, cachedToken)
}

// TestGetPosts tests the GetPosts method of the client by invoking the following steps:
// - Calls the GetEnvCredentials function to get the credentials from environment variables.
// - Creates a new client using the obtained URL, contentAPIKey, and adminAPIKey.
// - Retrieves a list of posts using the client's GetPosts method and passing the context.
// - Asserts that there is no error returned and the posts array is not empty.
func TestGetPosts(t *testing.T) {
	GetEnvCredentials()
	url, contentAPIKey, adminAPIKey := GetEnvCredentials()
	ghostClient := NewClient(url, WithContentAPIKey(contentAPIKey), WithAdminAPIKey(adminAPIKey))
	posts, err := ghostClient.GetPosts(context.Background())
	assert.NoError(t, err)
	assert.NotEmpty(t, posts[0].ID)
}
