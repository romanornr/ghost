package ghost

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

type HTTPMethod string

const (
	GET    HTTPMethod = http.MethodGet
	POST   HTTPMethod = http.MethodPost
	PUT    HTTPMethod = http.MethodPut
	DELETE HTTPMethod = http.MethodDelete
)

type Client interface {
	//	Do(req *http.Request) (*http.Response, error)
}

func WithHTTPTransport(transport http.RoundTripper) ClientOption {
	return func(c *client) {
		c.httpClient.Transport = transport
	}
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
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout:   10 * time.Second,
			Transport: http.DefaultTransport,
		},
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

func (c *client) getJWTToken(ctx context.Context) (string, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if c.jwtToken != "" && time.Now().Before(c.jwtExpiresAt) {
		return c.jwtToken, nil
	}

	token, expiredAt, err := c.generateJWTToken()
	if err != nil {
		return "", fmt.Errorf("failed to generate JWT token: %w", err)
	}

	c.jwtToken = token
	c.jwtExpiresAt = expiredAt

	return token, nil
}

func (c *client) generateJWTToken() (string, time.Time, error) {
	now := time.Now().Unix()

	// expire in 5 minutes
	expiresAt := now + 5*60

	keyParts := strings.Split(c.adminAPIKey, ":")
	if len(keyParts) != 2 {
		return "", time.Time{}, fmt.Errorf("invalid admin API key format")
	}

	id := keyParts[0]
	secret, err := hex.DecodeString(keyParts[1])
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to decode admin API key secret: %w", err)
	}

	claims := jwt.MapClaims{
		"aud": "/v3/admin/",
		"exp": expiresAt,
		"iat": now + 300,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token.Header["kid"] = id

	tokenString, err := token.SignedString(secret)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to sign JWT token: %w", err)
	}

	return tokenString, time.Unix(expiresAt, 0), nil
}

func (c *client) doRequest(ctx context.Context, method HTTPMethod, path string, body interface{}) (*http.Response, error) {
	url := fmt.Sprintf("%s%s", c.baseURL, path)

	var bodyReader io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(jsonBody)
	}

	req, err := http.NewRequestWithContext(ctx, string(method), url, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	if strings.Contains(path, "admin") {
		jwtToken, err := c.getJWTToken(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get JWT token: %w", err)
		}
		req.Header.Set("Authorization", "Ghost "+jwtToken)
	} else if c.contentAPIKey != "" {
		req.Header.Set("Authorization", "Ghost "+c.contentAPIKey)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		defer func() {
			closeErr := resp.Body.Close()
			if closeErr != nil {
				fmt.Printf("failed to close response body: %v", closeErr)
			}
		}()

		bodyBytes, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			return nil, fmt.Errorf("failed to read response body: %w", readErr)
		}

		return nil, fmt.Errorf("unexpected response status: %s; body %s", resp.Status, string(bodyBytes))
	}

	return resp, nil
}
