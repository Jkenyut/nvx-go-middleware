package main

import (
	"log"
	"net"

	mw "github.com/Jkenyut/nvx-go-middleware"
	"google.golang.org/grpc/reflection"
)

func main() {
	// 1. Initialize Middleware Manager
	mgr, err := mw.NewWithError(&mw.Config{
		Security: mw.ConfigSecurity{
			PublicKeySignature:  "your-rsa-public-key-here",
			PrivateKeySignature: "your-rsa-private-key-here",
			AllowedOrigins:      []string{"*"},
		},
		Core: mw.ConfigCore{
			Env:             "development",
			EnableTelemetry: true, // Enable OpenTelemetry
			ServiceName:     "my-grpc-service",
		},
	})
	if err != nil {
		log.Fatalf("Failed to initialize middleware manager: %v", err)
	}

	// 2. Setup gRPC Server using the Manager's Factory Method (Best Practice)
	// This automatically handles OTel StatsHandler and NVX interceptors safely.
	// It guarantees that telemetry is configured correctly if enabled.
	grpcServer := mgr.NewGRPCServer()

	// Register your service to grpcServer
	// pb.RegisterMyServiceServer(grpcServer, &server{})

	// Reflection to ease testing via Evans/grpcurl
	reflection.Register(grpcServer)

	// 3. Run the Server
	listener, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	log.Println("gRPC Server is running on port :50051 (with OpenTelemetry enabled)")
	if err := grpcServer.Serve(listener); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}
