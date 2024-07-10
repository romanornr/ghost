package ghost

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/gbrlsnchs/jwt/v3"
	_ "github.com/golang-jwt/jwt/v5"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	contentType           = "application/json"
	authorizationHeader   = "Authorization"
	authorizationToken    = "Ghost"
	jwtAudience           = "/admin"
	tokenExpirationPeriod = 5 * time.Minute
	httpClientTimeout     = 10 * time.Second
)

//type Ghost struct {
//	AdminAPIToken      string
//	ContentAPIToken    string
//	URL                string
//	jwtToken           string
//	jwtTokenExpiration time.Time
//	client             *http.Client
//}

type Ghost struct {
	adminAPIToken      string
	contentAPIToken    string
	jwtToken           string
	jwtTokenExpiration time.Time
	url                string
}

//func NewGhost(url, contentAPIToken, adminAPIToken string) (*Ghost, error) {
//	if url == "" || contentAPIToken == "" || adminAPIToken == "" {
//		return nil, fmt.Errorf("url, contentAPIToken and adminAPIToken are required")
//	}
//	return &Ghost{
//		URL:             url,
//		ContentAPIToken: contentAPIToken,
//		AdminAPIToken:   adminAPIToken,
//		client:          &http.Client{Timeout: httpClientTimeout},
//	}, nil
//}

func New(url, contentAPIToken, adminAPIToken string) *Ghost {
	return &Ghost{
		adminAPIToken:   adminAPIToken,
		contentAPIToken: contentAPIToken,
		url:             url,
	}
}

//func (g *Ghost) checkAndRenewJWTToken() error {
//	//if g.jwtToken == "" || g.jwtTokenExpiration.Before(time.Now()) {
//	//	jwtToken, jwtTokenExpiration, err := g.getJWTToken()
//	//	if err != nil {
//	//		return fmt.Errorf("failed to get JWT token: %v", err)
//	//	}
//	//}
//	//g.jwtToken = jwtToken
//	//g.jwtTokenExpiration = jwtTokenExpiration
//	//return nil
//	if g.jwtToken == "" || g.jwtTokenExpiration.Before(time.Now()) {
//		jwtToken, jwtTokenExpiration, err := g.getJWTToken()
//		if err != nil {
//			return fmt.Errorf("failed to generate JWT: %w", err)
//		}
//		g.jwtToken = jwtToken
//		g.jwtTokenExpiration = jwtTokenExpiration
//	}
//	return nil
//}

func (g *Ghost) checkAndRenewJWT() error {
	if g.jwtToken == "" || g.jwtTokenExpiration.Before(time.Now()) {
		jwtToken, jwtTokenExpiration, err := generateJWT(g.adminAPIToken)
		if err != nil {
			return err
		}
		g.jwtToken = jwtToken
		g.jwtTokenExpiration = jwtTokenExpiration
	}
	return nil
}

//func generateJWT(keyID string) (string, time.Time, error) {
//	keyParts := strings.Split(keyID, ":")
//	if len(keyParts) != 2 {
//		return "", time.Time{}, fmt.Errorf("invalid admin API token format")
//	}
//
//	id := keyParts[0]
//	rawSecret := keyParts[1]
//	secret := make([]byte, hex.DecodedLen(len(rawSecret)))
//	_, err := hex.Decode(secret, []byte(rawSecret))
//	if err != nil {
//		return "", time.Time{}, fmt.Errorf("failed to decode secret: %v", err)
//	}
//
//	now := time.Now()
//	expirationTime := now.Add(tokenExpirationPeriod)
//
//	//token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
//	//	"Audience":       jwt.WithAudience(jwtAudience),
//	//	"ExpirationTime": jwt.NewNumericDate(expirationTime),
//	//	"IssuedAt":       jwt.NewNumericDate(now),
//	//})
//
//	claims := jwt.RegisteredClaims{
//		Audience:  jwt.ClaimStrings{jwtAudience},
//		ExpiresAt: jwt.NewNumericDate(expirationTime),
//		IssuedAt:  jwt.NewNumericDate(now),
//		ID:        id,
//	}
//
//	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
//
//	tokenString, err := token.SignedString(secret)
//	if err != nil {
//		return "", time.Time{}, fmt.Errorf("failed to sign token: %v", err)
//	}
//
//	return tokenString, expirationTime, nil
//}

func generateJWT(keyID string) (string, time.Time, error) {
	var now = time.Now()
	var expiration = now.Add(5 * time.Minute)

	keyParts := strings.Split(keyID, ":")
	if len(keyParts) != 2 {
		return "", expiration, fmt.Errorf("invalid Client.Key format")
	}
	id := keyParts[0]
	rawSecret := []byte(keyParts[1])
	secret := make([]byte, hex.DecodedLen(len(rawSecret)))
	_, err := hex.Decode(secret, rawSecret)
	if err != nil {
		return "", expiration, err
	}

	hs256 := jwt.NewHS256(secret)
	p := jwt.Payload{
		Audience:       jwt.Audience{"/v5/admin/"},
		ExpirationTime: jwt.NumericDate(expiration),
		IssuedAt:       jwt.NumericDate(now),
	}
	token, err := jwt.Sign(p, hs256, jwt.KeyID(id))
	if err != nil {
		return "", expiration, err
	}
	return string(token), expiration, nil
}

var myClient = &http.Client{Timeout: 10 * time.Second}

func (g *Ghost) getJson(url string, target interface{}) error {
	if err := g.checkAndRenewJWT(); err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodGet, url, bytes.NewBuffer([]byte{}))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Ghost"+" "+g.jwtToken)
	resp, err := myClient.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			fmt.Printf("Cannot close body reader: %v\n", err)
		}
	}()

	err = parsePostResponse(resp, err, target)
	if err != nil {
		return err
	}
	return nil
}

func parsePostResponse(resp *http.Response, err error, target interface{}) error {
	content, _ := io.ReadAll(resp.Body)
	responseBody := string(content[:])

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("unexpected status code %d: %s", resp.StatusCode, responseBody)
	}

	err = json.Unmarshal(content, target)
	if err != nil {
		return err
	}
	return nil
}

func (g *Ghost) postJson(url string, data []byte, target interface{}) error {
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(data))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Ghost"+" "+g.jwtToken)
	resp, err := myClient.Do(req)
	if err != nil {
		return err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			fmt.Printf("Error closing body: %v\n", err)
		}
	}(resp.Body)

	err = parsePostResponse(resp, err, target)
	if err != nil {
		return err
	}

	return nil
}
