package ghost

import (
	"net/http"
	"sync"
	"time"
)

type Client interface {
}

// client represents a client for making API requests to a server.
// HTTP client for making the requests, JWT token and its expiration time, and a mutex to provide thread-safe access to the client.
type client struct {
	baseURL       string
	contentAPIKey string
	adminAPIKey   string
	httpClient    *http.Client

	jwtToken     string
	jwtExpiresAt time.Time
	mutex        sync.Mutex
}

type ClientOption func(*client)

// NewClient creates a new client with the specified baseURL and optional client options.
// It returns a Client interface. The client options can be used to customize the client behavior.
// The options are applied to the client in the order they are provided.
// Example usage:
//
//	client := NewClient("https://api.example.com", WithTimeout(30*time.Second), WithRetry(3))
func NewClient(baseURL string, opts ...ClientOption) Client {
	c := &client{
		baseURL:    baseURL,
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}

	// Apply the options to the client
	for _, opt := range opts {
		opt(c)
	}
	return c
}

func withContentAPIKey(key string) ClientOption {
	return func(c *client) {
		c.contentAPIKey = key
	}
}

func withAdminAPIKey(key string) ClientOption {
	return func(c *client) {
		c.adminAPIKey = key
	}
}

func withHTTPClient(httpClient *http.Client) ClientOption {
	// Return a function that sets the HTTP client on the client
	return func(c *client) {
		c.httpClient = httpClient
	}
}
