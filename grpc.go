package middleware

import (
	"cmp"
	"context"
	"fmt"
	"runtime/debug"
	"time"

	"github.com/Jkenyut/nvx-go-helper/activity"
	"github.com/Jkenyut/nvx-go-helper/cryptoutil"
	"github.com/Jkenyut/nvx-go-helper/format"
	"github.com/Jkenyut/nvx-go-middleware/model"
	"github.com/Jkenyut/nvx-go-telemetry/telemetry"
	"github.com/bytedance/sonic"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func mdValue(md metadata.MD, key string) string {
	if vals := md.Get(key); len(vals) > 0 {
		return vals[0]
	}
	return ""
}

func (m *Manager) prepareGRPCRequest(
	ctx context.Context,
	fullMethod, methodType, protocol string,
	bodyRequest any,
) (context.Context, metadata.MD, string, model.AuditLog) {
	md, _ := metadata.FromIncomingContext(ctx)

	correlationID := cmp.Or(mdValue(md, m.cfg.Headers.Keys.CorrelationID), cryptoutil.V7())
	requestID := mdValue(md, m.cfg.Headers.Keys.RequestID)
	userID := mdValue(md, m.cfg.Headers.Keys.UserID)
	ip := mdValue(md, m.cfg.Headers.Keys.IP)
	ipOrigin := mdValue(md, m.cfg.Headers.Keys.IPOrigin)
	userAgent := mdValue(md, "user-agent")

	ctx = activity.WithActivity(ctx, activity.Activity{
		CorrelationID: correlationID,
		RequestID:     requestID,
		UserID:        userID,
		UserIP:        ip,
		UserIPOrigin:  ipOrigin,
	})

	if m.cfg.Core.EnableTelemetry {
		span := trace.SpanFromContext(ctx)
		if !span.SpanContext().IsValid() {
			m.cfg.Logger.Error().Msg("🔥 WARNING: EnableTelemetry=true but otelgrpc is missing! You forgot to use grpc.StatsHandler(otelgrpc.NewServerHandler()) or mgr.NewGRPCServer()")
		} else {
			span.SetAttributes(
				attribute.String("service", m.cfg.Core.ServiceName),
				attribute.String("correlation_id", correlationID),
				attribute.String("request_id", requestID),
				attribute.String("ip", ip),
				attribute.String("ip_origin", ipOrigin),
				attribute.String("user_id", userID),
				attribute.String("user_agent", userAgent),
			)
		}
	}

	entry := model.AuditLog{
		ID:             cryptoutil.V7(),
		Method:         methodType,
		FullURL:        fullMethod,
		IP:             ip,
		IPOrigin:       ipOrigin,
		RequestID:      requestID,
		CreatedBy:      format.ToInt64(userID),
		CreatedAt:      format.NowUTC(),
		CorrelationID:  correlationID,
		RequestHeaders: maskMetadataJSON(md, m.cfg.Logging.MaskKeywords),
		RequestBody:    bodyRequest,
		Protocol:       protocol,
		ServiceName:    m.cfg.Core.ServiceName,
		UserAgent:      userAgent,
	}

	return ctx, md, correlationID, entry
}

func grpcAuditStatusCode(err error) (int, string) {
	if err == nil {
		return 200, ""
	}
	if st, ok := status.FromError(err); ok {
		return int(st.Code()), err.Error()
	}
	return 500, err.Error()
}

// GRPCUnaryInterceptor returns a gRPC unary server interceptor that provides:
//   - Correlation ID generation / propagation from incoming metadata
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
		var bodyRequest any
		if m.cfg.Logging.LogRequestBodies && req != nil {
			reqBytes, _ := sonic.ConfigDefault.Marshal(req)
			bodyRequest = normalizeBodyRaw(reqBytes, m.cfg.Logging.MaskKeywords)
		}

		ctx, md, correlationID, entry := m.prepareGRPCRequest(ctx, info.FullMethod, "POST", "gRPC Unary", bodyRequest)
		start := time.Now()

		defer func() {
			entry.StatusCode, entry.ErrorMessage = grpcAuditStatusCode(err)
			entry.LatencyMS = time.Since(start).Milliseconds()

			if m.cfg.Logging.LogResponseBodies && resp != nil {
				respBytes, _ := sonic.ConfigDefault.Marshal(resp)
				entry.ResponseBody = normalizeBodyRaw(respBytes, m.cfg.Logging.MaskKeywords)
			}

			if saveErr := m.saveAuditLog(ctx, &entry); saveErr != nil {
				m.cfg.Logger.Error().
					Str("correlation_id", correlationID).
					Err(saveErr).
					Msg("failed to save grpc audit log")
			}
		}()

		// Panic recovery
		defer func() {
			if rec := recover(); rec != nil {
				if m.cfg.Core.EnableTelemetry {
					telemetry.RecordError(trace.SpanFromContext(ctx), fmt.Errorf("panic recovered: %v", rec))
				}
				stack := string(debug.Stack())
				m.cfg.Logger.Error().
					Str("service", m.cfg.Core.ServiceName).
					Str("correlation_id", correlationID).
					Str("method", info.FullMethod).
					Str("request_id", mdValue(md, m.cfg.Headers.Keys.RequestID)).
					Str("ip", mdValue(md, m.cfg.Headers.Keys.IP)).
					Str("ip_origin", mdValue(md, m.cfg.Headers.Keys.IPOrigin)).
					Str("user_id", mdValue(md, m.cfg.Headers.Keys.UserID)).
					Str("user_agent", mdValue(md, "user-agent")).
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
//   - Correlation ID generation / propagation from incoming metadata
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
		ctx, _, correlationID, entry := m.prepareGRPCRequest(ss.Context(), info.FullMethod, "STREAM", "gRPC Stream", nil)
		wrapped := &wrappedServerStream{ServerStream: ss, ctx: ctx}
		start := time.Now()

		defer func() {
			entry.StatusCode, entry.ErrorMessage = grpcAuditStatusCode(err)
			entry.LatencyMS = time.Since(start).Milliseconds()

			if saveErr := m.saveAuditLog(ctx, &entry); saveErr != nil {
				m.cfg.Logger.Error().
					Str("correlation_id", correlationID).
					Err(saveErr).
					Msg("failed to save grpc stream audit log")
			}
		}()

		defer func() {
			if rec := recover(); rec != nil {
				if m.cfg.Core.EnableTelemetry {
					telemetry.RecordError(trace.SpanFromContext(ctx), fmt.Errorf("panic recovered: %v", rec))
				}
				stack := string(debug.Stack())
				m.cfg.Logger.Error().
					Str("service", m.cfg.Core.ServiceName).
					Str("correlation_id", correlationID).
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

func maskMetadataJSON(md metadata.MD, maskKeywords []string) []byte {
	return marshalAndMaskJSON(md, maskKeywords)
}
