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

	// Wrap the mux with the Logger, EnsureHeaders, and SecureHeaders middleware
	// Chain: Logger -> EnsureHeaders -> SecureHeaders -> Mux
	handler := middleware.Logger(middleware.EnsureHeaders(middleware.SecureHeaders(mux)))

	fmt.Println("Server executing on port 8080")
	log.Fatal(http.ListenAndServe(":8080", handler))
}

const version = "1.0.0"
