package ghost

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
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

// MembersResponse represents the API response structure for members
type MembersResponse struct {
	Members []Member `json:"members"`
	Meta    struct {
		Pagination PaginationInfo `json:"pagination"`
	} `json:"meta"`
}

// PaginationInfo represents the pagination metadata from Ghost's API
type PaginationInfo struct {
	Page  int `json:"page"`
	Limit int `json:"limit"`
	Pages int `json:"pages"`
	Total int `json:"total"`
	Next  int `json:"next,omitempty"`
	Prev  int `json:"prev,omitempty"`
}

// Member represents a member entity with detailed attributes including id, uuid, email, name, and subscription info.
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

// Subscription represents a subscription entity, including the customer's details and the subscription's status and pricing.
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

// GetAllMembers retrieves all members from the server using pagination
func (c *client) GetAllMembers(ctx context.Context) ([]Member, error) {
	var allMembers []Member
	page := 1
	limit := 100 // Ghost's default limit

	for {
		members, response, err := c.getMembersPage(ctx, page, limit)
		if err != nil {
			return nil, fmt.Errorf("failed to get members page %d: %w", page, err)
		}

		allMembers = append(allMembers, members...)

		// Check if we've retrieved all pages
		if page >= response.Meta.Pagination.Pages {
			break
		}

		page++
	}

	return allMembers, nil
}

// getMembersPage retrieves a single page of members from the server
func (c *client) getMembersPage(ctx context.Context, page, limit int) ([]Member, MembersResponse, error) {
	path := fmt.Sprintf("/ghost/api/v3/admin/members/?page=%d&limit=%d", page, limit)

	resp, err := c.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, MembersResponse{}, fmt.Errorf("failed to get members: %w", err)
	}

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			fmt.Printf("failed to close response body: %v", err)
		}
	}(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, MembersResponse{}, fmt.Errorf("unexpected response status: %s", resp.Status)
	}

	var membersResp MembersResponse
	if err := json.NewDecoder(resp.Body).Decode(&membersResp); err != nil {
		return nil, MembersResponse{}, fmt.Errorf("failed to decode members response: %w", err)
	}

	return membersResp.Members, membersResp, nil
}

// GetPaidAndCompedMembers retrieves all paid and comped members in paginated form and returns them as a collection.
func (c *client) GetPaidAndCompedMembers(ctx context.Context) (Members, error) {
	var allMembers []Member
	page := 1
	limit := 100

	for {
		members, response, err := c.getPaidMembersPage(ctx, page, limit)
		if err != nil {
			return Members{}, fmt.Errorf("failed to get paid members page %d: %w", page, err)
		}

		allMembers = append(allMembers, members...)

		// Check if we've retrieved all pages
		if page >= response.Meta.Pagination.Pages {
			break
		}

		page++
	}

	return Members{allMembers}, nil
}

// getPaidMembersPage retrieves a paginated list of paid members from the Ghost API.
// ctx: context for the request.
// page: page number to retrieve.
// limit: number of members per page.
// Returns a slice of Member, *MembersResponse, and error.
func (c *client) getPaidMembersPage(ctx context.Context, page, limit int) ([]Member, *MembersResponse, error) {
	query := url.Values{}
	query.Add("page", fmt.Sprintf("%d", page))
	query.Add("limit", fmt.Sprintf("%d", limit))
	query.Add("filter", "status:-free") // Ghost's filter for non-free members
	query.Add("include", "subscriptions")

	path := fmt.Sprintf("/ghost/api/v3/admin/members/?%s", query.Encode())

	resp, err := c.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get members: %w", err)
	}

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			fmt.Printf("failed to close response body: %v", err)
		}
	}(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("unexpected response status: %s", resp.Status)
	}

	var membersResp MembersResponse
	if err := json.NewDecoder(resp.Body).Decode(&membersResp); err != nil {
		return nil, nil, fmt.Errorf("failed to decode members response: %w", err)
	}

	return membersResp.Members, &membersResp, nil
}
