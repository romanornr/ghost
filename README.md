# Golang library for the Ghost API

[Ghost](https://ghost.org/) is a powerful open source publishing platform. This is a Golang client for the Ghost API.

## Installation

```bash
go get github.com/romanornr/ghost
go mod init github.com/your-username/your-repo
go mod tidy
```

## Usage

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

## Supported features

### Posts
* [x] Get all posts

### Members
* [x] Get all members
* [ ] Get member by ID
* [ ] Get member by email
* [ ] Create member
* [ ] Update member
* [ ] Delete member
