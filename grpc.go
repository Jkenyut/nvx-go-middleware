package middleware

import (
	"context"
	"fmt"
	"runtime/debug"
	"time"

	"github.com/Jkenyut/nvx-go-helper/activity"
	"github.com/Jkenyut/nvx-go-helper/cryptoutil"
	"github.com/Jkenyut/nvx-go-helper/format"
	"github.com/Jkenyut/nvx-go-middleware/model"
	"github.com/bytedance/sonic"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"go.opentelemetry.io/otel/attribute"
	otelcodes "go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
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
		transactionID := get(m.cfg.Headers.Keys.TransactionID)
		if transactionID == "" {
			transactionID = cryptoutil.V7()
		}

		// Enrich context
		ctx = activity.WithTransactionID(ctx, transactionID)
		ctx = activity.WithRequestID(ctx, get(m.cfg.Headers.Keys.RequestID))
		ctx = activity.WithAPIKey(ctx, get(m.cfg.Headers.Keys.APIKey))
		ctx = activity.WithUserID(ctx, get(m.cfg.Headers.Keys.UserID))
		ctx = activity.WithUserIP(ctx, get(m.cfg.Headers.Keys.IP))
		ctx = activity.WithUserIPOrigin(ctx, get(m.cfg.Headers.Keys.IPOrigin))

		if m.cfg.Core.EnableTelemetry {
			span := trace.SpanFromContext(ctx)
			if !span.SpanContext().IsValid() {
				m.cfg.Logger.Error().Msg("🔥 WARNING: EnableTelemetry=true but otelgrpc is missing! You forgot to use grpc.StatsHandler(otelgrpc.NewServerHandler()) or mgr.NewGRPCServer()")
			} else {
				span.SetAttributes(
					attribute.String("service", m.cfg.Core.ServiceName),
					attribute.String("transaction_id", transactionID),
					attribute.String("request_id", get(m.cfg.Headers.Keys.RequestID)),
					attribute.String("ip", get(m.cfg.Headers.Keys.IP)),
					attribute.String("user_id", get(m.cfg.Headers.Keys.UserID)),
					attribute.String("ip_origin", get(m.cfg.Headers.Keys.IPOrigin)),
					attribute.String("user_agent", get("user-agent")),
				)
			}
		}

		start := time.Now()

		IDAuditLog := cryptoutil.V7()
		b, _ := sonic.ConfigDefault.Marshal(md)
		str := format.MaskAfterKeywords(string(b), m.cfg.Logging.MaskKeywords, "*")
		reqHeadersBytes := []byte(str)

		var bodyRequest any
		if m.cfg.Logging.LogRequestBodies && req != nil {
			reqBytes, _ := sonic.ConfigDefault.Marshal(req)
			bodyRequest = normalizeBodyRaw(reqBytes, m.cfg.Logging.MaskKeywords)
		}

		entry := model.AuditLog{
			ID:              IDAuditLog,
			Method:          "POST",
			FullURL:         info.FullMethod,
			StatusCode:      0,
			LatencyMS:       0,
			IP:              get(m.cfg.Headers.Keys.IP),
			IPOrigin:        get(m.cfg.Headers.Keys.IPOrigin),
			RequestID:       get(m.cfg.Headers.Keys.RequestID),
			CreatedBy:       format.ToInt64(get(m.cfg.Headers.Keys.UserID)),
			CreatedAt:       format.NowUTC(),
			TransactionID:   transactionID,
			RequestHeaders:  reqHeadersBytes,
			ResponseHeaders: nil,
			RequestBody:     bodyRequest,
			ResponseBody:    nil,
			Protocol:        "gRPC Unary",
			ServiceName:     m.cfg.Core.ServiceName,
			UserAgent:       get("user-agent"),
			ErrorMessage:    "",
		}

		reqCtx := context.WithoutCancel(ctx)

		defer func() {
			statusCode := 200
			if err != nil {
				entry.ErrorMessage = err.Error()
				if st, ok := status.FromError(err); ok {
					statusCode = int(st.Code())
				} else {
					statusCode = 500
				}
			}

			entry.StatusCode = statusCode
			entry.LatencyMS = time.Since(start).Milliseconds()

			if m.cfg.Logging.LogResponseBodies && resp != nil {
				respBytes, _ := sonic.ConfigDefault.Marshal(resp)
				entry.ResponseBody = normalizeBodyRaw(respBytes, m.cfg.Logging.MaskKeywords)
			}

			if saveErr := m.cfg.LogStore.Save(reqCtx, &entry); saveErr != nil {
				m.cfg.Logger.Error().
					Str("transaction_id", transactionID).
					Err(saveErr).
					Msg("failed to save grpc audit log")
			}
		}()

		// Panic recovery
		defer func() {
			if rec := recover(); rec != nil {
				if m.cfg.Core.EnableTelemetry {
					span := trace.SpanFromContext(ctx)
					span.RecordError(fmt.Errorf("panic: %v", rec))
					span.SetStatus(otelcodes.Error, "panic recovered")
				}
				stack := string(debug.Stack())
				m.cfg.Logger.Error().
					Str("service", m.cfg.Core.ServiceName).
					Str("transaction_id", transactionID).
					Str("method", info.FullMethod).
					Str("request_id", get(m.cfg.Headers.Keys.RequestID)).
					Str("ip", get(m.cfg.Headers.Keys.IP)).
					Str("ip_origin", get(m.cfg.Headers.Keys.IPOrigin)).
					Str("user_id", get(m.cfg.Headers.Keys.UserID)).
					Str("user_agent", get("user-agent")).
					Interface("panic", rec).
					Msgf("gRPC unary panic:\n%s", stack)
				err = status.Errorf(codes.Internal, "internal server error")
			}
		}()

		resp, err = handler(ctx, req)

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

		transactionID := get(m.cfg.Headers.Keys.TransactionID)
		if transactionID == "" {
			transactionID = cryptoutil.V7()
		}

		ctx = activity.WithTransactionID(ctx, transactionID)
		ctx = activity.WithRequestID(ctx, get(m.cfg.Headers.Keys.RequestID))
		ctx = activity.WithAPIKey(ctx, get(m.cfg.Headers.Keys.APIKey))
		ctx = activity.WithUserID(ctx, get(m.cfg.Headers.Keys.UserID))
		ctx = activity.WithUserIP(ctx, get(m.cfg.Headers.Keys.IP))
		ctx = activity.WithUserIPOrigin(ctx, get(m.cfg.Headers.Keys.IPOrigin))

		if m.cfg.Core.EnableTelemetry {
			span := trace.SpanFromContext(ctx)
			if !span.SpanContext().IsValid() {
				m.cfg.Logger.Error().Msg("🔥 WARNING: EnableTelemetry=true but otelgrpc is missing! You forgot to use grpc.StatsHandler(otelgrpc.NewServerHandler()) or mgr.NewGRPCServer()")
			} else {
				span.SetAttributes(
					attribute.String("service", m.cfg.Core.ServiceName),
					attribute.String("transaction_id", transactionID),
					attribute.String("request_id", get(m.cfg.Headers.Keys.RequestID)),
					attribute.String("ip", get(m.cfg.Headers.Keys.IP)),
					attribute.String("ip_origin", get(m.cfg.Headers.Keys.IPOrigin)),
					attribute.String("user_id", get(m.cfg.Headers.Keys.UserID)),
					attribute.String("user_agent", get("user-agent")),
				)
			}
		}

		wrapped := &wrappedServerStream{ServerStream: ss, ctx: ctx}
		start := time.Now()

		IDAuditLog := cryptoutil.V7()
		b, _ := sonic.ConfigDefault.Marshal(md)
		str := format.MaskAfterKeywords(string(b), m.cfg.Logging.MaskKeywords, "*")
		reqHeadersBytes := []byte(str)

		entry := model.AuditLog{
			ID:              IDAuditLog,
			Method:          "STREAM",
			FullURL:         info.FullMethod,
			StatusCode:      0,
			LatencyMS:       0,
			IP:              get(m.cfg.Headers.Keys.IP),
			IPOrigin:        get(m.cfg.Headers.Keys.IPOrigin),
			RequestID:       get(m.cfg.Headers.Keys.RequestID),
			CreatedBy:       format.ToInt64(get(m.cfg.Headers.Keys.UserID)),
			CreatedAt:       format.NowUTC(),
			TransactionID:   transactionID,
			RequestHeaders:  reqHeadersBytes,
			ResponseHeaders: nil,
			RequestBody:     nil,
			ResponseBody:    nil,
			Protocol:        "gRPC Stream",
			ServiceName:     m.cfg.Core.ServiceName,
			UserAgent:       get("user-agent"),
			ErrorMessage:    "",
		}

		reqCtx := context.WithoutCancel(ctx)

		defer func() {
			statusCode := 200
			if err != nil {
				entry.ErrorMessage = err.Error()
				if st, ok := status.FromError(err); ok {
					statusCode = int(st.Code())
				} else {
					statusCode = 500
				}
			}

			entry.StatusCode = statusCode
			entry.LatencyMS = time.Since(start).Milliseconds()

			if saveErr := m.cfg.LogStore.Save(reqCtx, &entry); saveErr != nil {
				m.cfg.Logger.Error().
					Str("transaction_id", transactionID).
					Err(saveErr).
					Msg("failed to save grpc stream audit log")
			}
		}()

		defer func() {
			if rec := recover(); rec != nil {
				if m.cfg.Core.EnableTelemetry {
					span := trace.SpanFromContext(ctx)
					span.RecordError(fmt.Errorf("panic: %v", rec))
					span.SetStatus(otelcodes.Error, "panic recovered")
				}
				stack := string(debug.Stack())
				m.cfg.Logger.Error().
					Str("service", m.cfg.Core.ServiceName).
					Str("transaction_id", transactionID).
					Str("method", info.FullMethod).
					Interface("panic", rec).
					Msgf("gRPC stream panic:\n%s", stack)
				err = status.Errorf(codes.Internal, "internal server error")
			}
		}()

		err = handler(srv, wrapped)

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

// NewGRPCServer creates a new gRPC server automatically configured with
// OTel StatsHandler (if telemetry is enabled) and NVX interceptors.
// This is the recommended way to create a gRPC server to avoid missing configurations.
func (m *Manager) NewGRPCServer(opts ...grpc.ServerOption) *grpc.Server {
	var defaultOpts []grpc.ServerOption

	if m.cfg.Core.EnableTelemetry {
		defaultOpts = append(defaultOpts, grpc.StatsHandler(otelgrpc.NewServerHandler()))
	}

	defaultOpts = append(defaultOpts,
		grpc.ChainUnaryInterceptor(m.GRPCUnaryInterceptor()),
		grpc.ChainStreamInterceptor(m.GRPCStreamInterceptor()),
	)

	return grpc.NewServer(append(defaultOpts, opts...)...)
}
