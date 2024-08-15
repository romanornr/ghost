package ghost

import (
	"bytes"
	"context"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"io"
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

// GetEnvCredentials gets credentials from environment variables.
func GetEnvCredentials() (string, string, string) {
	ghostURL := os.Getenv("GHOST_URL")
	contentAPIKey := os.Getenv("CONTENT_API_KEY")
	adminAPIKey := os.Getenv("ADMIN_API_KEY")

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
	baseURL := "https://ghost.romanornr.io"
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

func TestDoRequest(t *testing.T) {
	//mockClient := new(MockHTTPClient)
	mockTripper := new(MockRoundTripper)
	c := NewClient(
		"https://ghost.romanornr.io",
		WithHTTPTransport(mockTripper),
	).(*client)

	ctx := context.Background()
	mockResp := &http.Response{
		StatusCode: http.StatusOK,
		//Body:       http.NoBody,
		Body: io.NopCloser(bytes.NewBufferString(`{"success": true}`)),
	}

	//mockTripper.On("Do", mock.Anything).Return(mockResponse, nil)
	mockTripper.On("RoundTrip", mock.AnythingOfType("*http.Request")).Return(mockResp, nil).Once()

	resp, err := c.doRequest(ctx, http.MethodGet, "/test", nil)
	assert.NoError(t, err)
	assert.Equal(t, mockResp, resp)
	mockTripper.AssertExpectations(t)
}

func TestGetPosts(t *testing.T) {
	mockTripper := new(MockRoundTripper)
	c := NewClient(
		"https://ghost.romanornr.io",
		WithHTTPTransport(mockTripper),
	).(*client)

	ctx := context.Background()

	mockRespBody := `{"posts": [{"id": "1", "title": "Test Post"}]}`

	mockResp := &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewBufferString(mockRespBody)),
	}

	mockTripper.On("RoundTrip", mock.AnythingOfType("*http.Request")).Return(mockResp, nil).Once()

	posts, err := c.GetPosts(ctx)

	assert.NoError(t, err)
	assert.Len(t, posts, 1)
	assert.Equal(t, "1", posts[0].ID)
	assert.Equal(t, "Test Post", posts[0].Title)

	mockTripper.AssertExpectations(t)

}
