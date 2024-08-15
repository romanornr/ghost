package ghost

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

type Post struct {
	ID                 string `json:"id,omitempty"`
	UUID               string `json:"uuid,omitempty"`
	Title              string `json:"title,omitempty"`
	MobileDoc          string `json:"mobiledoc,omitempty"`
	Slug               string `json:"slug,omitempty"`
	HTML               string `json:"html,omitempty"`
	CommentID          string `json:"comment_id,omitempty"`
	FeatureImage       string `json:"feature_image,omitempty"`
	Featured           bool   `json:"featured,omitempty"`
	Page               bool   `json:"page,omitempty"`
	MetaTitle          string `json:"meta_title,omitempty"`
	MetaDescription    string `json:"meta_description,omitempty"`
	CreatedAt          string `json:"created_at,omitempty"`   // "2022-01-05T22:39:28.000Z"
	UpdatedAt          string `json:"updated_at,omitempty"`   // "2022-04-02T16:01:24.000Z"
	PublishedAt        string `json:"published_at,omitempty"` // "2022-01-19T06:31:00.000Z"
	CustomExcerpt      string `json:"custom_excerpt,omitempty"`
	OGImage            string `json:"og_image,omitempty"`
	OGTitle            string `json:"og_title,omitempty"`
	OGDescription      string `json:"og_description,omitempty"`
	TwitterImage       string `json:"twitter_image,omitempty"`
	TwitterTitle       string `json:"twitter_title,omitempty"`
	TwitterDescription string `json:"twitter_description,omitempty"`
	CustomTemplate     string `json:"custom_template,omitempty"`
	URL                string `json:"url,omitempty"`
	Excerpt            string `json:"excerpt,omitempty"`
	Tags               []Tag  `json:"tags,omitempty"`
	Status             string `json:"status,omitempty"`     // "published"
	Visibility         string `json:"visibility,omitempty"` // "public"
}

type Posts struct {
	Posts []Post `json:"posts"`
}

func (c *client) GetPosts(ctx context.Context) ([]Post, error) {
	resp, err := c.doRequest(ctx, GET, "/ghost/api/v3/content/posts", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get posts: %w", err)
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			fmt.Printf("failed to close response body: %v", err)
		}
	}(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected response status: %s", resp.Status)
	}

	var postsResp Posts
	if err := json.NewDecoder(resp.Body).Decode(&postsResp); err != nil {
		return nil, fmt.Errorf("failed to decode posts response: %w", err)
	}

	return postsResp.Posts, nil
}
