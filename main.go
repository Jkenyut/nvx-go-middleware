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

	// Initialize the LogStore
	// In the future, you can swap this with a DatabaseStore or FileStore
	logStore := &middleware.ConsoleStore{}

	// Wrap the mux with the middleware chain
	// Chain: Recoverer -> Logger -> EnforceMethods -> EnsureHeaders -> SecureHeaders -> Mux
	handler := middleware.Recoverer(
		middleware.Logger(
			logStore,
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
