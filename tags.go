package ghost

import "time"

type Tags struct {
	Tags []Tag `json:"tags"`
}

type Tag struct {
	CreatedAt          time.Time `json:"created_at,omitempty"`
	Description        string    `json:"description,omitempty"`
	FeatureImage       string    `json:"feature_image,omitempty"`
	Id                 string    `json:"id,omitempty"`
	MetaDescription    string    `json:"meta_description,omitempty"`
	MetaTitle          string    `json:"meta_title,omitempty"`
	Name               string    `json:"name,omitempty"`
	Slug               string    `json:"slug,omitempty"`
	UpdatedAt          time.Time `json:"updated_at,omitempty"`
	Url                string    `json:"url,omitempty"`
	Visibility         string    `json:"visibility,omitempty"`
	TwitterImage       string    `json:"twitter_image,omitempty"`
	TwitterTitle       string    `json:"twitter_title,omitempty"`
	TwitterDescription string    `json:"twitter_description,omitempty"`
	CodeInjectionHead  string    `json:"codeinjection_head,omitempty"`
	CodeInjectionFoot  string    `json:"codeinjection_foot,omitempty"`
	CanonicalURL       string    `json:"canonical_url,omitempty"`
	AccentColor        string    `json:"accent_color,omitempty"`
	Count              struct {
		Posts int `json:"posts,omitempty"`
	} `json:"count,omitempty,skip"`
}

type NewTags struct {
	Tags []NewTag `json:"tags"`
}

// NewTag - two struct because field "Count" must not exist when creating a new tag
type NewTag struct {
	CreatedAt          time.Time `json:"created_at,omitempty"`
	Description        string    `json:"description,omitempty"`
	FeatureImage       string    `json:"feature_image,omitempty"`
	Id                 string    `json:"id,omitempty"`
	MetaDescription    string    `json:"meta_description,omitempty"`
	MetaTitle          string    `json:"meta_title,omitempty"`
	Name               string    `json:"name,omitempty"`
	Slug               string    `json:"slug,omitempty"`
	UpdatedAt          time.Time `json:"updated_at,omitempty"`
	Url                string    `json:"url,omitempty"`
	Visibility         string    `json:"visibility,omitempty"`
	TwitterImage       string    `json:"twitter_image,omitempty"`
	TwitterTitle       string    `json:"twitter_title,omitempty"`
	TwitterDescription string    `json:"twitter_description,omitempty"`
	CodeInjectionHead  string    `json:"codeinjection_head,omitempty"`
	CodeInjectionFoot  string    `json:"codeinjection_foot,omitempty"`
	CanonicalURL       string    `json:"canonical_url,omitempty"`
	AccentColor        string    `json:"accent_color,omitempty"`
}
