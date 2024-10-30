package ghost

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"io"
	"log"
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

// Client is an interface that defines methods for interacting with a remote API.
// Implementations of the Client interface should provide functionality for retrieving posts
// and members from the API. The GetPosts method retrieves a list of posts, and the GetMembers method
// retrieves a list of members. Both methods accept a context.Context parameter for cancellation
// and deadline propagation.
type Client interface {
	GetPosts(ctx context.Context) ([]Post, error)
	GetMembers(ctx context.Context) (Members, error)
	GetAllMembers(ctx context.Context) ([]Member, error)
	GetPaidAndCompedMembers(ctx context.Context) (Members, error)
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
//	client := NewClient("https://api.example.com", client.WithAdminAPIKey("admin-key"))
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

func WithContentAPIKey(key string) ClientOption {
	return func(c *client) {
		c.contentAPIKey = key
	}
}

func WithAdminAPIKey(key string) ClientOption {
	return func(c *client) {
		c.adminAPIKey = key
	}
}

func WithHTTPClient(httpClient *http.Client) ClientOption {
	// Return a function that sets the HTTP client on the client
	return func(c *client) {
		c.httpClient = httpClient
	}
}

// getJWTToken retrieves a JWT token for API authentication.
// If the token is already available and not expired, it returns the token without generating a new one.
// Otherwise, it calls generateJWTToken to generate a new token, updates the client's jwtToken and jwtExpiresAt fields,
// and returns the generated token.
// It acquires a lock on the client mutex to ensure thread-safe access to the client fields.
// It returns the JWT token as a string and an error if it fails to generate the token.
func (c *client) getJWTToken(ctx context.Context) (string, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if c.jwtToken != "" && time.Now().Before(c.jwtExpiresAt) {
		return c.jwtToken, nil
	}

	token, expiredAt, err := c.generateJWTToken(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to generate JWT token: %w", err)
	}

	c.jwtToken = token
	c.jwtExpiresAt = expiredAt

	return token, nil
}

// generateJWTToken generates a JWT token with the necessary claims and headers.
// It uses the admin API key and its secret to sign the token using the HS256 signing method.
// The token expires in 5 minutes from the current time.
// It returns the generated token as a string, the expiration time, and an error if it fails to generate the token.
func (c *client) generateJWTToken(ctx context.Context) (string, time.Time, error) {

	type result struct {
		token     string
		expiresAt time.Time
		err       error
	}

	resultCh := make(chan result)

	go func() {

		defer close(resultCh)

		//expire in 5 minutes
		now := time.Now().Unix()
		expiresAt := now + 5*60

		keyParts := strings.Split(c.adminAPIKey, ":")
		if len(keyParts) != 2 {
			resultCh <- result{err: fmt.Errorf("invalid admin API key format")}
		}

		id := keyParts[0]
		secret, decodeErr := hex.DecodeString(keyParts[1])
		if decodeErr != nil {
			resultCh <- result{err: fmt.Errorf("failed to decode admin API key secret: %w", decodeErr)}
		}

		claims := jwt.MapClaims{
			"aud": "/v3/admin/",
			"exp": expiresAt,
			"iat": now + 300,
		}

		jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		jwtToken.Header["kid"] = id

		token, err := jwtToken.SignedString(secret)
		if err != nil {
			resultCh <- result{err: fmt.Errorf("failed to sign JWT token: %w", err)}
			return
		}
		resultCh <- result{token: token, expiresAt: time.Unix(expiresAt, 0)}
	}()

	// Wait for the operation to complete or the context to be canceled
	select {
	case <-ctx.Done():
		return "", time.Time{}, ctx.Err()
	case r, ok := <-resultCh:
		if !ok {
			return "", time.Time{}, fmt.Errorf("channel closed unexpectedly")
		}
		return r.token, r.expiresAt, r.err
	}
}

// ensureAuth ensures that the client has a valid JWT token. If the token is empty or expired,
// it generates a new JWT token and updates the client's jwtToken and jwtExpiresAt fields.
// It acquires a lock on the client mutex to ensure thread-safe access to the client fields.
// It returns an error if it fails to generate the JWT token.
func (c *client) ensureAuth(ctx context.Context) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if c.jwtToken == "" || time.Now().After(c.jwtExpiresAt) {
		token, expiresAt, err := c.generateJWTToken(ctx)
		if err != nil {
			return fmt.Errorf("failed to generate JWT token: %w", err)
		}

		c.jwtToken = token
		c.jwtExpiresAt = expiresAt
	}
	return nil
}

// doRequest sends an HTTP request to the specified URL using the given HTTP method.
// It optionally includes a request body and adds the necessary headers, including the JWT token.
// It returns the HTTP response and an error if the request fails.
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

	req.Header.Set("Content-Type", "application/json")

	jwtToken, err := c.getJWTToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get JWT token: %w", err)
	}

	req.Header.Set("Authorization", "Ghost "+jwtToken)
	req.Header.Add("Accept-Version", "v3.0")

	log.Printf("Making request to: %s", url)
	log.Printf("Headers: %v", req.Header)

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
