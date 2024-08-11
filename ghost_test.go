package ghost

import (
	"fmt"
	"testing"
)

func TestClient(t *testing.T) {
	ghostClient := NewClient("https://api.example.com")
	// print client options
	fmt.Println(ghostClient)
}
