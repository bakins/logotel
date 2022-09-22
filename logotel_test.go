package logotel_test

import (
	"bytes"
	"context"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"

	"github.com/matryer/is"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	colLogsV1 "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	logsv1 "go.opentelemetry.io/proto/otlp/logs/v1"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/bakins/logotel"
)

func TestGrpcExporter(t *testing.T) {
	is := is.New(t)

	sr := tracetest.NewSpanRecorder()
	tp := trace.NewTracerProvider(trace.WithSpanProcessor(sr))
	otel.SetTracerProvider(tp)

	s := newServer()
	g := grpc.NewServer()
	colLogsV1.RegisterLogsServiceServer(g, s)

	svr := httptest.NewServer(h2c.NewHandler(g, &http2.Server{}))
	defer svr.Close()

	u, err := url.Parse(svr.URL)
	is.NoErr(err)

	exporter, err := logotel.NewGrpcExporter(context.Background(), u.Host, grpc.WithTransportCredentials(insecure.NewCredentials()))
	is.NoErr(err)

	resource := resource.NewWithAttributes("", attribute.String("resource-key", "resource-value"))
	l := logotel.NewLogger().WithExporter(exporter).WithResource(resource)

	ctx := logotel.ToContext(context.Background(), l)

	ctx, span := otel.Tracer("testing").Start(ctx, "my-span")
	defer span.End()

	logotel.Info(ctx, "testing 1234", attribute.String("my-key", "my-value"))

	var protoLog logsv1.ResourceLogs
	err = protojson.Unmarshal(s.buf.Bytes(), &protoLog)
	is.NoErr(err)

	is.True(protoLog.Resource != nil)
	is.Equal(1, len(protoLog.Resource.Attributes))
	is.Equal("resource-value", protoLog.Resource.Attributes[0].Value.GetStringValue())
	is.Equal(1, len(protoLog.ScopeLogs))
	is.Equal(1, len(protoLog.ScopeLogs[0].LogRecords))
	is.Equal("testing 1234", protoLog.ScopeLogs[0].LogRecords[0].Body.GetStringValue())
	is.Equal(1, len(protoLog.ScopeLogs[0].LogRecords[0].Attributes))
	is.Equal("my-value", protoLog.ScopeLogs[0].LogRecords[0].Attributes[0].Value.GetStringValue())
	is.True(protoLog.ScopeLogs[0].LogRecords[0].TraceId != nil)
	is.True(protoLog.ScopeLogs[0].LogRecords[0].SpanId != nil)
}

func newServer() *server {
	s := server{}

	s.exporter = logotel.NewJSONExporter().WithWriter(&s.buf)

	return &s
}

type server struct {
	sync.Mutex
	buf bytes.Buffer
	colLogsV1.UnimplementedLogsServiceServer
	exporter *logotel.JSONExporter
}

func (s *server) Export(ctx context.Context, req *colLogsV1.ExportLogsServiceRequest) (*colLogsV1.ExportLogsServiceResponse, error) {
	s.Lock()
	defer s.Unlock()

	err := s.exporter.ExportLogs(ctx, req.ResourceLogs)
	if err != nil {
		return nil, err
	}
	return &colLogsV1.ExportLogsServiceResponse{}, nil
}
