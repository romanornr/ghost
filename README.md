# Golang library for the Ghost API

A Go client library for the Ghost Content and Admin API. This client provides a simple way to interact with your Ghost blog programmatically.

[Ghost](https://ghost.org/) is a powerful open source publishing platform. This is a Golang client for the Ghost API.

## Features

* [x] Full support for Ghost Admin API v3
* [x] Support for both Content API and Admin API
* [x] Automatic JWT token handling and refresh
* [x] Automatic pagination handling
* [x] Built-in filtering for member types
* [ ] Proper error handling and context support
* [ ] Get member by ID
* [ ] Get member by email
* [ ] Create member
* [ ] Update member
* [ ] Delete member


## Installation

```bash
go get github.com/romanornr/ghost
go mod init github.com/your-username/your-repo
go mod tidy
```

## Usage

### Initialize the client
```go
import "github.com/romanornr/ghost"

// Load credentials from environment variables
ghostURL := os.Getenv("GHOST_URL")
contentAPIKey := os.Getenv("GHOST_CONTENT_API_TOKEN")
adminAPIKey := os.Getenv("GHOST_ADMIN_API_TOKEN")

// Create a new client
client := ghost.NewClient(
    ghostURL,
    ghost.WithContentAPIKey(contentAPIKey),
    ghost.WithAdminAPIKey(adminAPIKey),
)
```

### Working with Posts
```go
// Get all posts
posts, err := client.GetPosts(context.Background())
if err != nil {
    log.Fatal(err)
}

for _, post := range posts {
    fmt.Printf("Title: %s\nSlug: %s\n", post.Title, post.Slug)
}
```

### Working with Members

```go
members, err := client.GetAllMembers(context.Background())
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Total members: %d\n", len(members.Members))
```

### Get paid and comped members
```go
paidMembers, err := client.GetPaidAndCompedMembers(context.Background())
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Total paid/comped members: %d\n", len(paidMembers.Members))

// Iterate through paid members
for _, member := range paidMembers.Members {
    fmt.Printf("Name: %s, Email: %s, Status: %s\n", 
        member.Name, 
        member.Email, 
        member.Status)
}
```

### Member details 
```go
type Member struct {
    Id                string          `json:"id"`
    Email             string          `json:"email"`
    Name              string          `json:"name"`
    Status            string          `json:"status"`
    Subscribed        bool            `json:"subscribed"`
    Subscriptions     []Subscription  `json:"subscriptions"`
    // ... other fields
}
```


### Example
```go
package main

import (
    "fmt"
    "github.com/romanornr/ghost"
    "context"
)

func main() {
    client := ghost.NewClient("http://example.ghost.io", ghost.WithAdminAPIKey("your-admin-api-key"), ghost.WithContentAPIKey("your-content-api-key"))
    ctx := context.Background()
    posts, err := client.GetPosts(ctx)
    if err != nil {
        fmt.Println(err)
    }
    for _, post := range posts {
        fmt.Println(post.Title)
    }
}
```