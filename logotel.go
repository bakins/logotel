package logotel

import (
	"context"
	"io"
	"os"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/trace"
	colLogsV1 "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	commonv1 "go.opentelemetry.io/proto/otlp/common/v1"
	logsv1 "go.opentelemetry.io/proto/otlp/logs/v1"
	resourcev1 "go.opentelemetry.io/proto/otlp/resource/v1"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protojson"
)

// Debug is a helper that uses the Logger in the context.
func Debug(ctx context.Context, message string, attributes ...attribute.KeyValue) {
	FromContext(ctx).Debug(ctx, message, attributes...)
}

// Info is a helper that uses the Logger in the context.
func Info(ctx context.Context, message string, attributes ...attribute.KeyValue) {
	FromContext(ctx).Info(ctx, message, attributes...)
}

// Warn is a helper that uses the Logger in the context.
func Warn(ctx context.Context, message string, attributes ...attribute.KeyValue) {
	FromContext(ctx).Warn(ctx, message, attributes...)
}

// Error is a helper that uses the Logger in the context.
func Error(ctx context.Context, message string, attributes ...attribute.KeyValue) {
	FromContext(ctx).Error(ctx, message, attributes...)
}

// Fatal is a helper that uses the Logger in the context.
func Fatal(ctx context.Context, message string, attributes ...attribute.KeyValue) {
	FromContext(ctx).Fatal(ctx, message, attributes...)
}

type contextKey struct {
	key string
}

var logContextKey = &contextKey{key: "log"}

var nop = &Logger{}

// FromContext returns the Logger from the context.
// If no logger was added, a nop Logger is returned.
func FromContext(ctx context.Context) *Logger {
	l, ok := ctx.Value(logContextKey).(*Logger)
	if !ok || l == nil {
		return nop
	}

	return l
}

// ToContext adds the Logger to the context.
func ToContext(ctx context.Context, l *Logger) context.Context {
	return context.WithValue(ctx, logContextKey, l)
}

// Logger is an opentelemetry logger
type Logger struct {
	exporter      Exporter
	resource      *resourcev1.Resource
	scope         *commonv1.InstrumentationScope
	errorReporter func(ctx context.Context, err error)
	attributes    []*commonv1.KeyValue
	severity      logsv1.SeverityNumber
}

// NewLogger creates a new Logger at Info severity.
// It does nothing with logs, so you must add an exporter.
func NewLogger() *Logger {
	l := Logger{
		severity: logsv1.SeverityNumber_SEVERITY_NUMBER_INFO,
	}

	return &l
}

// Debug logs at debug severity. Attributes passed here are merged with those added WithAttributes.
func (l *Logger) Debug(ctx context.Context, message string, attributes ...attribute.KeyValue) {
	l.log(ctx, logsv1.SeverityNumber_SEVERITY_NUMBER_DEBUG, message, attributes)
}

// Info logs at info severity. Attributes passed here are merged with those added WithAttributes.
func (l *Logger) Info(ctx context.Context, message string, attributes ...attribute.KeyValue) {
	l.log(ctx, logsv1.SeverityNumber_SEVERITY_NUMBER_INFO, message, attributes)
}

// Warn logs at warn severity. Attributes passed here are merged with those added WithAttributes.
func (l *Logger) Warn(ctx context.Context, message string, attributes ...attribute.KeyValue) {
	l.log(ctx, logsv1.SeverityNumber_SEVERITY_NUMBER_WARN, message, attributes)
}

// Error logs at error severity. Attributes passed here are merged with those added WithAttributes.
func (l *Logger) Error(ctx context.Context, message string, attributes ...attribute.KeyValue) {
	l.log(ctx, logsv1.SeverityNumber_SEVERITY_NUMBER_ERROR, message, attributes)
}

// Fatal logs at fatal severity. Attributes passed here are merged with those added WithAttributes.
func (l *Logger) Fatal(ctx context.Context, message string, attributes ...attribute.KeyValue) {
	l.log(ctx, logsv1.SeverityNumber_SEVERITY_NUMBER_ERROR, message, attributes)
}

// WithSeverity returns a clone of the logger with the given severity.
// Logs below this severity will not be exported.
func (l *Logger) WithSeverity(severity logsv1.SeverityNumber) *Logger {
	n := *l
	n.severity = severity

	return &n
}

// WithResource returns a clone of the logger with the given resource.
// The resource is included with the exporter log records.
// This overrides any previously set resource.
func (l *Logger) WithResource(resource *resource.Resource) *Logger {
	n := *l

	iter := resource.Iter()

	attributes := make([]*commonv1.KeyValue, 0, iter.Len())

	for iter.Next() {
		a := iter.Attribute()
		attributes = append(attributes, convertAttribute(a))
	}

	res := resourcev1.Resource{
		Attributes: attributes,
	}

	n.resource = &res

	return &n
}

// WithExporter returns a clone of the logger with the given exporter.
// This overrides any previously set exporter.
func (l *Logger) WithExporter(exporter Exporter) *Logger {
	n := *l
	n.exporter = exporter
	return &n
}

// WithResource returns a clone of the logger with the attributes
// merged with any existing ones on the Logger.
func (l *Logger) WithAttributes(attributes ...attribute.KeyValue) *Logger {
	n := *l
	n.attributes = mergeAttributes(l.attributes, convertAttributes(attributes))
	return &n
}

// Exporter exports log records
type Exporter interface {
	ExportLogs(ctx context.Context, protoLogs []*logsv1.ResourceLogs) error
}

func convertAttribute(a attribute.KeyValue) *commonv1.KeyValue {
	switch a.Value.Type() {
	case attribute.BOOL:
		return &commonv1.KeyValue{
			Key: string(a.Key),
			Value: &commonv1.AnyValue{
				Value: &commonv1.AnyValue_BoolValue{
					BoolValue: a.Value.AsBool(),
				},
			},
		}
	case attribute.STRING:
		return &commonv1.KeyValue{
			Key: string(a.Key),
			Value: &commonv1.AnyValue{
				Value: &commonv1.AnyValue_StringValue{
					StringValue: a.Value.AsString(),
				},
			},
		}
	default:
		return nil
	}
}

func convertAttributes(attributes []attribute.KeyValue) []*commonv1.KeyValue {
	out := make([]*commonv1.KeyValue, 0, len(attributes))

	for _, a := range attributes {
		if kv := convertAttribute(a); kv != nil {
			out = append(out, kv)
		}
	}

	return out
}

func mergeAttributes(base []*commonv1.KeyValue, override []*commonv1.KeyValue) []*commonv1.KeyValue {
	if len(base) == 0 {
		return override
	}

	if len(override) == 0 {
		return base
	}

	merged := make(map[string]*commonv1.KeyValue, len(base)+len(override))

	for _, kv := range base {
		merged[kv.Key] = kv
	}

	for _, kv := range override {
		merged[kv.Key] = kv
	}

	out := make([]*commonv1.KeyValue, 0, len(merged))
	for _, kv := range merged {
		out = append(out, kv)
	}

	return out
}

func (l *Logger) log(ctx context.Context, severity logsv1.SeverityNumber, message string, attributes []attribute.KeyValue) {
	if l == nil || l.severity > severity || l.exporter == nil {
		return
	}

	now := uint64(time.Now().UnixNano())

	logRecord := logsv1.LogRecord{
		TimeUnixNano:         now,
		ObservedTimeUnixNano: now,
		SeverityNumber:       logsv1.SeverityNumber(severity),
		SeverityText:         severity.String(),
		Body: &commonv1.AnyValue{
			Value: &commonv1.AnyValue_StringValue{
				StringValue: message,
			},
		},
		Attributes: mergeAttributes(l.attributes, convertAttributes(attributes)),
	}

	spanContext := trace.SpanContextFromContext(ctx)
	if traceID := spanContext.TraceID(); traceID.IsValid() {
		id := traceID[:]
		logRecord.TraceId = id

		traceFlags := spanContext.TraceFlags()
		// TODO:correctly convert this
		logRecord.Flags = uint32(traceFlags)

		if spanID := spanContext.SpanID(); spanID.IsValid() {
			id := spanID[:]
			logRecord.SpanId = id
		}
	}

	scopeLog := logsv1.ScopeLogs{
		Scope: l.scope,
		LogRecords: []*logsv1.LogRecord{
			&logRecord,
		},
	}

	protoLog := logsv1.ResourceLogs{
		Resource: l.resource,
		ScopeLogs: []*logsv1.ScopeLogs{
			&scopeLog,
		},
	}

	err := l.exporter.ExportLogs(ctx, []*logsv1.ResourceLogs{&protoLog})
	if err != nil && l.errorReporter != nil {
		l.errorReporter(ctx, err)
	}
}

// GrpcExporter exports logs using the oltp grpc log export service.
type GrpcExporter struct {
	client  colLogsV1.LogsServiceClient
	timeout time.Duration
}

// NewGrpcExporter creates an exporter.
func NewGrpcExporter(ctx context.Context, address string, options ...grpc.DialOption) (*GrpcExporter, error) {
	conn, err := grpc.DialContext(ctx, address, options...)
	if err != nil {
		return nil, err
	}

	g := GrpcExporter{
		client:  colLogsV1.NewLogsServiceClient(conn),
		timeout: time.Second * 5,
	}

	return &g, nil
}

// ExportLogs exports logs.
func (g *GrpcExporter) ExportLogs(_ context.Context, protoLogs []*logsv1.ResourceLogs) error {
	// we use our own context for exporting as passed in one may be tied to request
	// and have metadata, etc
	ctx, cancel := context.WithTimeout(context.Background(), g.timeout)
	defer cancel()

	req := colLogsV1.ExportLogsServiceRequest{
		ResourceLogs: protoLogs,
	}

	_, err := g.client.Export(ctx, &req)

	return err
}

type lockedWriter struct {
	sync.Mutex
	writer io.Writer
}

func newLockedWriter(w io.Writer) *lockedWriter {
	if lw, ok := w.(*lockedWriter); ok {
		// no need to layer on another lock
		return lw
	}
	return &lockedWriter{writer: w}
}

func (s *lockedWriter) Write(bs []byte) (int, error) {
	s.Lock()
	n, err := s.writer.Write(bs)
	s.Unlock()
	return n, err
}

var stdout = newLockedWriter(os.Stdout)

// JSONExporter writes logs in json format.
type JSONExporter struct {
	writer io.Writer
}

// NewJSONExporter creates a new exported that writes json to stdout.
func NewJSONExporter() *JSONExporter {
	j := JSONExporter{
		writer: stdout,
	}

	return &j
}

// WithWriter sets the writer for the exporter.
// It is up to the caller to ensure the writer is locked.
// The exported writes logs one complete line at a time.
func (j *JSONExporter) WithWriter(w io.Writer) *JSONExporter {
	n := *j
	n.writer = w

	return &n
}

// ExportLogs exports logs.
func (j *JSONExporter) ExportLogs(_ context.Context, protoLogs []*logsv1.ResourceLogs) error {
	for _, l := range protoLogs {
		data, err := protojson.Marshal(l)
		if err != nil {
			continue
		}

		data = append(data, []byte("\n")...)

		_, _ = j.writer.Write(data)
	}

	return nil
}
