package ghost

import (
	"encoding/hex"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
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

type Ghost struct {
	AdminAPIToken      string
	ContentAPIToken    string
	URL                string
	jwtToken           string
	jwtTokenExpiration time.Time
	client             *http.Client
}

func NewGhost(url, contentAPIToken, adminAPIToken string) (*Ghost, error) {
	if url == "" || contentAPIToken == "" || adminAPIToken == "" {
		return nil, fmt.Errorf("url, contentAPIToken and adminAPIToken are required")
	}
	return &Ghost{
		URL:             url,
		ContentAPIToken: contentAPIToken,
		AdminAPIToken:   adminAPIToken,
		client:          &http.Client{Timeout: httpClientTimeout},
	}, nil
}

func (g *Ghost) checkAndRenewJWTToken() error {
	//if g.jwtToken == "" || g.jwtTokenExpiration.Before(time.Now()) {
	//	jwtToken, jwtTokenExpiration, err := g.getJWTToken()
	//	if err != nil {
	//		return fmt.Errorf("failed to get JWT token: %v", err)
	//	}
	//}
	//g.jwtToken = jwtToken
	//g.jwtTokenExpiration = jwtTokenExpiration
	//return nil
	if g.jwtToken == "" || g.jwtTokenExpiration.Before(time.Now()) {
		jwtToken, jwtTokenExpiration, err := g.getJWTToken()
		if err != nil {
			return fmt.Errorf("failed to generate JWT: %w", err)
		}
		g.jwtToken = jwtToken
		g.jwtTokenExpiration = jwtTokenExpiration
	}
	return nil
}

func (g *Ghost) getJWTToken() (string, time.Time, error) {
	keyParts := strings.Split(g.AdminAPIToken, ":")
	if len(keyParts) != 2 {
		return "", time.Time{}, fmt.Errorf("invalid admin API token format")
	}

	id := keyParts[0]
	rawSecret := keyParts[1]
	secret := make([]byte, hex.DecodedLen(len(rawSecret)))
	_, err := hex.Decode(secret, []byte(rawSecret))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to decode secret: %v", err)
	}

	now := time.Now()
	expirationTime := now.Add(tokenExpirationPeriod)

	//token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
	//	"Audience":       jwt.WithAudience(jwtAudience),
	//	"ExpirationTime": jwt.NewNumericDate(expirationTime),
	//	"IssuedAt":       jwt.NewNumericDate(now),
	//})

	claims := jwt.RegisteredClaims{
		Audience:  jwt.ClaimStrings{jwtAudience},
		ExpiresAt: jwt.NewNumericDate(expirationTime),
		IssuedAt:  jwt.NewNumericDate(now),
		ID:        id,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString(secret)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to sign token: %v", err)
	}

	return tokenString, expirationTime, nil
}
