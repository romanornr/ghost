package ghost

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type Members struct {
	Members []Member `json:"members"`
}

type NewMembers struct {
	Members []NewMember `json:"members"`
}

//const membersPath = "/ghost/api/admin/members/?key=%s&limit=all"
//const membersPathAll = "/ghost/api/v3/admin/members/?key=%s&limit=all"

type Member struct {
	Id          string      `json:"id"`
	Uuid        string      `json:"uuid"`
	Email       string      `json:"email"`
	Name        string      `json:"name"`
	Note        interface{} `json:"note"`
	Geolocation interface{} `json:"geolocation"`
	Subscribed  bool        `json:"subscribed"`
	CreatedAt   time.Time   `json:"created_at"`
	UpdatedAt   time.Time   `json:"updated_at"`
	Labels      []struct {
		Id        string    `json:"id"`
		Name      string    `json:"name"`
		Slug      string    `json:"slug"`
		CreatedAt time.Time `json:"created_at"`
		UpdatedAt time.Time `json:"updated_at"`
	} `json:"labels"`
	Subscriptions    []Subscription `json:"subscriptions"`
	AvatarImage      string         `json:"avatar_image"`
	EmailCount       int            `json:"email_count"`
	EmailOpenedCount int            `json:"email_opened_count"`
	EmailOpenRate    float64        `json:"email_open_rate"`
	Status           string         `json:"status"`
}

type NewMember struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

type Subscription struct {
	Id       string `json:"id"`
	Customer struct {
		Id    string `json:"id"`
		Name  string `json:"name"`
		Email string `json:"email"`
	} `json:"customer"`
	Status                  string    `json:"status"`
	StartDate               time.Time `json:"start_date"`
	DefaultPaymentCardLast4 string    `json:"default_payment_card_last4"`
	CancelAtPeriodEnd       bool      `json:"cancel_at_period_end"`
	CancellationReason      string    `json:"cancellation_reason"`
	CurrentPeriodEnd        time.Time `json:"current_period_end"`
	Price                   struct {
		Id       string `json:"id"`
		PriceId  string `json:"price_id"`
		Nickname string `json:"nickname"`
		Amount   int    `json:"amount"`
		Interval string `json:"interval"`
		Type     string `json:"type"`
		Currency string `json:"currency"`
	} `json:"price"`
}

// GetMembers retrieves all members from the server.
// It sends an HTTP GET request to the "/ghost/api/v3/admin/members/?limit=all" endpoint.
// It returns a Members object and an error if the request fails or the response cannot be decoded.
func (c *client) GetMembers(ctx context.Context) (Members, error) {
	const membersPathAll = "/ghost/api/v3/admin/members/?limit=all"
	resp, err := c.doRequest(ctx, http.MethodGet, membersPathAll, nil)
	if err != nil {
		return Members{}, fmt.Errorf("failed to get members: %w", err)
	}

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			fmt.Printf("failed to close response body: %v", err)
		}
	}(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return Members{}, fmt.Errorf("unexpected response status: %s", resp.Status)
	}

	var membersResp Members
	fmt.Printf("resp.Body: %v\n", resp.Body)
	if err := json.NewDecoder(resp.Body).Decode(&membersResp); err != nil {
		return Members{}, fmt.Errorf("failed to decode members response: %w", err)
	}

	return membersResp, nil
}
