package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/Jkenyut/nvx-go-middleware/middleware"
)

func main() {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello, World!"))
	})

	// Wrap the mux with the middleware chain
	// Chain: Recoverer -> Logger -> EnforceMethods -> EnsureHeaders -> SecureHeaders -> Mux
	// Note: Order matters. Recoverer should be outer-most to catch panics.
	// EnforceMethods should be early to reject invalid methods quickly.
	handler := middleware.Recoverer(
		middleware.Logger(
			middleware.EnforceMethods(
				middleware.EnsureHeaders(
					middleware.SecureHeaders(mux),
				),
			),
		),
	)

	fmt.Println("Server executing on port 8080")
	log.Fatal(http.ListenAndServe(":8080", handler))
}

const version = "1.0.0"
