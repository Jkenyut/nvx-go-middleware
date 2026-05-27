package middleware

import (
	"context"
	"runtime/debug"
	"time"

	"github.com/Jkenyut/nvx-go-helper/activity"
	"github.com/Jkenyut/nvx-go-helper/cryptoutil"
	"github.com/Jkenyut/nvx-go-middleware/constants"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// GRPCUnaryInterceptor returns a gRPC unary server interceptor that provides:
//   - Transaction ID generation / propagation from incoming metadata
//   - Context enrichment (user ID, API key, IP, etc.)
//   - Panic recovery with structured logging
//   - Request/response latency logging
func (m *Manager) GRPCUnaryInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (resp any, err error) {
		md, _ := metadata.FromIncomingContext(ctx)

		// Helpers to extract the first value of a metadata key
		get := func(key string) string {
			if vals := md.Get(key); len(vals) > 0 {
				return vals[0]
			}
			return ""
		}

		// Propagate / generate transaction ID
		transactionID := get(constants.HeaderTransactionID)
		if transactionID == "" {
			transactionID = cryptoutil.V7()
		}

		// Enrich context
		ctx = activity.WithTransactionID(ctx, transactionID)
		ctx = activity.WithRequestID(ctx, get(constants.HeaderRequestID))
		ctx = activity.WithAPIKey(ctx, get(constants.HeaderAPIKey))
		ctx = activity.WithUserID(ctx, get(constants.HeaderUserID))
		ctx = activity.WithUserIP(ctx, get(constants.HeaderIP))
		ctx = activity.WithUserType(ctx, get(constants.HeaderUserType))

		start := time.Now()

		// Panic recovery
		defer func() {
			if rec := recover(); rec != nil {
				stack := string(debug.Stack())
				m.cfg.Logger.Error().
					Str("service", m.cfg.ServiceName).
					Str("transaction_id", transactionID).
					Str("method", info.FullMethod).
					Interface("panic", rec).
					Msgf("gRPC unary panic:\n%s", stack)
				err = status.Errorf(codes.Internal, "internal server error")
			}
		}()

		resp, err = handler(ctx, req)

		m.cfg.Logger.Info().
			Str("service", m.cfg.ServiceName).
			Str("transaction_id", transactionID).
			Str("method", info.FullMethod).
			Interface("latency_ms", time.Since(start).Milliseconds()).
			Interface("error", err).
			Msg("gRPC unary call")

		return resp, err
	}
}

// GRPCStreamInterceptor returns a gRPC stream server interceptor that provides:
//   - Transaction ID generation / propagation from incoming metadata
//   - Context enrichment (user ID, API key, IP, etc.)
//   - Panic recovery with structured logging
//   - Stream open/close latency logging
func (m *Manager) GRPCStreamInterceptor() grpc.StreamServerInterceptor {
	return func(
		srv any,
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) (err error) {
		ctx := ss.Context()
		md, _ := metadata.FromIncomingContext(ctx)

		get := func(key string) string {
			if vals := md.Get(key); len(vals) > 0 {
				return vals[0]
			}
			return ""
		}

		transactionID := get(constants.HeaderTransactionID)
		if transactionID == "" {
			transactionID = cryptoutil.V7()
		}

		ctx = activity.WithTransactionID(ctx, transactionID)
		ctx = activity.WithRequestID(ctx, get(constants.HeaderRequestID))
		ctx = activity.WithAPIKey(ctx, get(constants.HeaderAPIKey))
		ctx = activity.WithUserID(ctx, get(constants.HeaderUserID))
		ctx = activity.WithUserIP(ctx, get(constants.HeaderIP))
		ctx = activity.WithUserType(ctx, get(constants.HeaderUserType))

		wrapped := &wrappedServerStream{ServerStream: ss, ctx: ctx}
		start := time.Now()

		defer func() {
			if rec := recover(); rec != nil {
				stack := string(debug.Stack())
				m.cfg.Logger.Error().
					Str("service", m.cfg.ServiceName).
					Str("transaction_id", transactionID).
					Str("method", info.FullMethod).
					Interface("panic", rec).
					Msgf("gRPC stream panic:\n%s", stack)
				err = status.Errorf(codes.Internal, "internal server error")
			}
		}()

		err = handler(srv, wrapped)

		m.cfg.Logger.Info().
			Str("service", m.cfg.ServiceName).
			Str("transaction_id", transactionID).
			Str("method", info.FullMethod).
			Interface("latency_ms", time.Since(start).Milliseconds()).
			Interface("error", err).
			Msg("gRPC stream call")

		return err
	}
}

// wrappedServerStream replaces the embedded context so that context-aware
// functions inside the handler receive the enriched context.
type wrappedServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (w *wrappedServerStream) Context() context.Context { return w.ctx }
