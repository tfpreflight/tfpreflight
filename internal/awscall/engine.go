package awscall

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/tfpreflight/tfpreflight/rules"
)

// Result is what a lookup established about one identifier.
type Result string

// Only Exists and NotFound are definite answers.
const (
	Exists   Result = "EXISTS"
	NotFound Result = "NOT_FOUND"
	// Unknown is every other answer. It is never read as absence.
	Unknown Result = "UNKNOWN"
)

// Engine sends the lookups Specs describe.
type Engine struct {
	Credentials aws.CredentialsProvider
	HTTPClient  interface {
		Do(*http.Request) (*http.Response, error)
	}
	// Partitions decide which partition's endpoints a region uses.
	Partitions []rules.Partition
	// Region is used when a lookup names none.
	Region string
	// BaseEndpoint and ConfigSources are the endpoint configuration an SDK
	// client reads.
	BaseEndpoint  *string
	ConfigSources []any
	fips          bool
	dualStack     bool
	discovery     bool
	// Retryer, RetryMode, MaxAttempts and DisableClockSkewCorrection are the SDK
	// client settings. Each service and region gets its own retryer, as each
	// client does.
	Retryer                    func() aws.Retryer
	RetryMode                  aws.RetryMode
	MaxAttempts                int
	DisableClockSkewCorrection bool
	// Sleep and Now are replaceable for tests.
	Sleep func(context.Context, time.Duration) error
	Now   func() time.Time

	signer  *v4.Signer
	mu      sync.Mutex
	clients map[string]*client
}

// New builds an engine from what a service client would read from config:
// credentials, HTTP client, region, endpoint settings and retries. partitions
// come from the spec pack.
func New(config aws.Config, partitions []rules.Partition) *Engine {
	var client interface {
		Do(*http.Request) (*http.Response, error)
	} = http.DefaultClient
	if config.HTTPClient != nil {
		client = config.HTTPClient
	}
	engine := &Engine{
		Credentials: config.Credentials, HTTPClient: client, signer: v4.NewSigner(),
		Partitions: partitions, Region: config.Region,
		BaseEndpoint: config.BaseEndpoint, ConfigSources: config.ConfigSources,
		Retryer: config.Retryer, RetryMode: config.RetryMode, MaxAttempts: config.RetryMaxAttempts,
		DisableClockSkewCorrection: config.DisableClockSkewCorrection,
	}
	engine.fips, engine.dualStack = endpointSettings(config.ConfigSources)
	engine.discovery = discoveryEnabled(config.ConfigSources)
	return engine
}

// Answer is what one lookup established and why, and what went wrong when it
// established nothing.
type Answer struct {
	Result Result
	// Reason is worded as the SDK adapters word theirs.
	Reason string
	// Failure says what went wrong when Result is Unknown.
	Failure *Failure
}

// Failure describes a lookup that established nothing, in one format for every
// protocol. The AWS fields hold only what AWS sent.
type Failure struct {
	Service, Operation string
	// Code, Status, RequestID and Message are what AWS answered with.
	Code      string
	Status    int
	RequestID string
	Message   string
	// Cause says what happened when AWS gave no usable answer.
	Cause string
}

// Error renders the failure as
//
//	<service>:<operation> failed: <ErrorCode> (HTTP <status>), request ID <id>
//	<message>
//
// leaving out what AWS did not send. With no AWS answer, the cause follows
// the colon instead.
func (f *Failure) Error() string {
	var b strings.Builder
	b.WriteString(f.Service + ":" + f.Operation + " failed: ")
	if f.Status == 0 {
		b.WriteString(f.Cause)
	} else {
		switch {
		case f.Cause != "" && f.Code == "":
			fmt.Fprintf(&b, "%s (HTTP %d)", f.Cause, f.Status)
		case f.Code != "":
			fmt.Fprintf(&b, "%s (HTTP %d)", f.Code, f.Status)
		default:
			fmt.Fprintf(&b, "HTTP %d", f.Status)
		}
		if f.RequestID != "" {
			b.WriteString(", request ID " + f.RequestID)
		}
	}
	if f.Message != "" {
		b.WriteString("\n" + f.Message)
	}
	return b.String()
}

// Lookup asks AWS whether id exists, and answers as the SDK adapters do.
func (e *Engine) Lookup(ctx context.Context, spec Spec, region, id string) (Result, string) {
	answer := e.Inspect(ctx, spec, region, map[string]string{spec.Field: id})
	return answer.Result, answer.Reason
}

// Inspect asks AWS about the object values identify, one value per input member.
// It retries as the SDK's retry middleware does: the SDK's retryer for this
// service and region, its retry quota and its clock skew correction.
func (e *Engine) Inspect(ctx context.Context, spec Spec, region string, values map[string]string) Answer {
	// Only reads are sent. Packs are checked when they load; this covers specs
	// from anywhere else.
	if err := spec.CheckReadOnly(); err != nil {
		return inspectionFailure(spec, "request not sent: not a read-only lookup", err.Error())
	}
	// The SDK validates required members before anything is sent.
	if len(spec.MissingRequired) > 0 {
		return inspectionFailure(spec, "request not sent: required "+strings.Join(spec.MissingRequired, ", ")+" not part of this lookup", "")
	}
	if region == "" {
		region = e.Region
	}
	where, err := e.Target(spec, region)
	if err != nil {
		return inspectionFailure(spec, "no endpoint", err.Error())
	}
	run := &inspection{e: e, c: e.client(spec.Service, region), spec: spec, where: where, values: values, releaseRetry: nopRelease}
	run.maxAttempts = run.c.retryer.MaxAttempts()
	if !e.DisableClockSkewCorrection {
		run.attemptSkew = time.Duration(run.c.skew.Load())
	}
	for attempt := 1; ; attempt++ {
		if ctx.Err() != nil {
			return e.canceled(ctx, spec)
		}
		sent, answer, done := run.attempt(ctx, attempt)
		if done {
			return answer
		}
		if answer, done := run.retry(ctx, attempt, sent); done {
			return answer
		}
	}
}

func inspectionFailure(spec Spec, cause, detail string) Answer {
	return Answer{Unknown, TransportFailure, &Failure{Service: spec.Service, Operation: spec.Operation, Cause: cause, Message: detail}}
}

type inspection struct {
	e            *Engine
	c            *client
	spec         Spec
	where        rules.Target
	values       map[string]string
	maxAttempts  int
	releaseRetry func(error) error
	attemptSkew  time.Duration
}

type sentAttempt struct {
	result  outcome
	skew    time.Duration
	hasSkew bool
}

// attempt sends one request and releases its tokens. done is true when the
// answer is final.
func (r *inspection) attempt(ctx context.Context, attempt int) (sentAttempt, Answer, bool) {
	releaseAttempt, err := r.c.retryer.GetAttemptToken(ctx)
	if err != nil {
		return sentAttempt{}, r.e.finish(ctx, r.c, outcome{spec: r.spec, values: r.values, failure: err}, false, 0), true
	}
	request, err := buildRequest(ctx, r.spec, r.where.URL, r.values)
	if err != nil {
		return sentAttempt{}, inspectionFailure(r.spec, "request not built", err.Error()), true
	}
	requestAt := r.e.now()
	status, header, body, sendErr := r.e.send(ctx, request, r.where.SigningName, r.where.SigningRegion, requestAt.Add(r.attemptSkew))
	sent := sentAttempt{result: r.e.outcome(r.spec, r.values, status, header, body, sendErr)}
	sent.skew, sent.hasSkew = clockSkew(header, requestAt, r.e.now())

	_ = r.releaseRetry(sent.result.err)
	if !sdkRevisedRetries() || attempt == 1 {
		_ = releaseAttempt(sent.result.err)
	}
	if sent.result.err == nil {
		return sent, r.e.finish(ctx, r.c, sent.result, sent.hasSkew, sent.skew), true
	}
	return sent, Answer{}, false
}

// retry decides whether a failed attempt is retried, and waits for it. done is
// true when the failure is final.
func (r *inspection) retry(ctx context.Context, attempt int, sent sentAttempt) (Answer, bool) {
	retryErr := sent.result.err
	if !r.e.DisableClockSkewCorrection {
		retryErr = wrapAsClockSkew(retryErr, sent.result.code, sent.skew, sent.hasSkew, r.attemptSkew)
	}
	if !r.c.retryer.IsErrorRetryable(retryErr) || r.maxAttempts > 0 && attempt >= r.maxAttempts {
		return r.e.finish(ctx, r.c, sent.result, sent.hasSkew, sent.skew), true
	}
	releaseRetry, err := r.c.retryer.GetRetryToken(ctx, retryErr)
	if err != nil {
		return r.e.finish(ctx, r.c, sent.result, sent.hasSkew, sent.skew), true
	}
	r.releaseRetry = releaseRetry
	index := attempt
	if sdkRevisedRetries() {
		index = attempt - 1
	}
	delay, err := r.c.retryer.RetryDelay(index, retryErr)
	if err != nil {
		return r.e.finish(ctx, r.c, outcome{spec: r.spec, values: r.values, failure: err}, sent.hasSkew, sent.skew), true
	}
	if r.e.sleep(ctx, delay) != nil {
		return r.e.canceled(ctx, r.spec), true
	}
	r.attemptSkew = 0
	if !r.e.DisableClockSkewCorrection && sent.hasSkew {
		r.attemptSkew = sent.skew
	}
	return Answer{}, false
}

func (e *Engine) canceled(ctx context.Context, spec Spec) Answer {
	reason := contextReason(ctx)
	return Answer{Unknown, reason, &Failure{Service: spec.Service, Operation: spec.Operation, Cause: reason}}
}

// outcome is one attempt's result. err is its error in the shape an SDK client
// gives it, which is what the SDK's retryer classifies.
type outcome struct {
	spec    Spec
	values  map[string]string
	status  int
	header  http.Header
	body    []byte
	code    string
	decoded bool
	failure error
	err     error
}

func (e *Engine) outcome(spec Spec, values map[string]string, status int, header http.Header, body []byte, sendErr error) outcome {
	if sendErr != nil {
		return outcome{spec: spec, values: values, failure: sendErr, err: &smithyhttp.RequestSendError{Err: sendErr}}
	}
	attempt := outcome{spec: spec, values: values, status: status, header: header, body: body}
	if status >= 200 && status < 300 {
		return attempt
	}
	attempt.code, attempt.decoded = errorCode(spec, status, header, body)
	code := attempt.code
	if code == "" {
		code = "UnknownError"
	}
	var cause error = &smithy.GenericAPIError{Code: code}
	if !attempt.decoded {
		cause = &smithy.DeserializationError{Err: errors.New("error response is not in the protocol's format")}
	}
	response := &http.Response{StatusCode: status, Header: header}
	attempt.err = &awshttp.ResponseError{ResponseError: &smithyhttp.ResponseError{Response: &smithyhttp.Response{Response: response}, Err: cause}}
	return attempt
}

// TransportFailure is the reason for any lookup AWS did not answer; the
// failure's cause says what happened. The SDK adapters use the same reason.
const TransportFailure = "AWS transport or inspection failure"

// finish turns the last attempt into the answer, and keeps the clock skew it saw
// for the client's next lookup, as the SDK does.
func (e *Engine) finish(ctx context.Context, c *client, attempt outcome, hasSkew bool, skew time.Duration) Answer {
	if !e.DisableClockSkewCorrection && hasSkew {
		c.skew.Store(int64(skew))
	}
	spec := attempt.spec
	failure := &Failure{Service: spec.Service, Operation: spec.Operation}
	unknown := func(reason string) Answer { return Answer{Unknown, reason, failure} }
	if attempt.failure != nil {
		if ctx.Err() != nil {
			return e.canceled(ctx, spec)
		}
		var credentials *credentialsError
		if errors.As(attempt.failure, &credentials) {
			failure.Cause, failure.Message = "no credentials", credentials.err.Error()
		} else {
			failure.Cause, failure.Message = "no response from AWS", attempt.failure.Error()
		}
		return unknown(TransportFailure)
	}
	failure.Status, failure.RequestID = attempt.status, requestID(spec, attempt.header, attempt.body)
	if attempt.err == nil {
		answer := succeeded(spec, attempt.body, attempt.values[spec.Field])
		if answer.Result == Unknown {
			failure.Cause = answer.Reason
			if answer.Reason == TransportFailure {
				failure.Cause = "response could not be read"
			}
			answer.Failure = failure
		}
		return answer
	}
	if !attempt.decoded {
		failure.Cause = "error response could not be read"
		return unknown(TransportFailure)
	}
	failure.Code, failure.Message = attempt.code, errorMessage(spec, attempt.body)
	code := attempt.code
	if code == "" {
		code = "UnknownError"
	}
	if slices.Contains(spec.NotFound.Codes, code) {
		return Answer{Result: NotFound, Reason: "authoritative not-found: " + code}
	}
	if isType(spec, code) {
		return Answer{Result: NotFound, Reason: "authoritative not-found: modelled " + spec.NotFound.Type}
	}
	return unknown("AWS inspection error: " + code)
}

func nopRelease(error) error { return nil }

// sdkRevisedRetries reports whether the AWS SDK's revised retry behaviour is
// on. AWS_NEW_RETRIES_2026 is the SDK's own opt-in; the engine follows it so
// its retries match an SDK client's.
func sdkRevisedRetries() bool { return os.Getenv("AWS_NEW_RETRIES_2026") == "true" }

// client is what an SDK client keeps between requests: its retryer and retry
// quota, and the last clock skew.
type client struct {
	retryer aws.RetryerV2
	skew    atomic.Int64
}

func (e *Engine) client(service, region string) *client {
	e.mu.Lock()
	defer e.mu.Unlock()
	key := service + "\x00" + region
	if c, ok := e.clients[key]; ok {
		return c
	}
	if e.clients == nil {
		e.clients = map[string]*client{}
	}
	c := &client{retryer: e.newRetryer()}
	e.clients[key] = c
	return c
}

// newRetryer builds a retryer as an SDK client does from the same configuration.
func (e *Engine) newRetryer() aws.RetryerV2 {
	retryer := e.baseRetryer()
	if e.MaxAttempts != 0 {
		retryer = retry.AddWithMaxAttempts(retryer, e.MaxAttempts)
	}
	if v2, ok := retryer.(aws.RetryerV2); ok {
		return v2
	}
	return retryerV2{retryer}
}

func (e *Engine) baseRetryer() aws.Retryer {
	if e.Retryer != nil {
		return e.Retryer()
	}
	var standard []func(*retry.StandardOptions)
	if v := e.MaxAttempts; v != 0 {
		standard = append(standard, func(so *retry.StandardOptions) { so.MaxAttempts = v })
	}
	if e.RetryMode != aws.RetryModeAdaptive {
		return retry.NewStandard(standard...)
	}
	var adaptive []func(*retry.AdaptiveModeOptions)
	if len(standard) != 0 {
		adaptive = append(adaptive, func(ao *retry.AdaptiveModeOptions) { ao.StandardOptions = append(ao.StandardOptions, standard...) })
	}
	return retry.NewAdaptiveMode(adaptive...)
}

// retryerV2 adapts a plain retryer as the SDK's middleware does.
type retryerV2 struct{ aws.Retryer }

// GetAttemptToken provides a retry token for the AWS SDK retry interface.
func (r retryerV2) GetAttemptToken(context.Context) (func(error) error, error) {
	return r.GetInitialToken(), nil
}

// clockSkewCodes and skewThreshold are the SDK retry middleware's.
var clockSkewCodes = map[string]bool{
	"InvalidSignatureException": true, "SignatureDoesNotMatch": true, "AuthFailure": true,
	"RequestTimeTooSkewed": true, "AccessDeniedException": true,
}

const skewThreshold = 4 * time.Minute

// clockSkew is the server's clock less this one's at the request's
// midpoint, from the response's Date header, as the SDK measures it.
func clockSkew(header http.Header, requestAt, responseAt time.Time) (time.Duration, bool) {
	date := header.Get("Date")
	if date == "" || header.Get("Age") != "" {
		return 0, false
	}
	server, err := smithyhttp.ParseTime(date)
	if err != nil {
		return 0, false
	}
	elapsed := responseAt.Sub(requestAt)
	if elapsed > 15*time.Minute {
		return 0, false
	}
	return server.Sub(requestAt.Add(elapsed / 2)), true
}

// skewError marks an error the clock may have caused, which is retried.
type skewError struct{ err error }

// Error describes the clock-skew failure.
func (e *skewError) Error() string { return "probable clock skew error: " + e.err.Error() }

// Unwrap returns the AWS error that indicated clock skew.
func (e *skewError) Unwrap() error { return e.err }

// RetryableError reports that correcting the clock may make this call succeed.
func (e *skewError) RetryableError() bool { return true }

func wrapAsClockSkew(err error, code string, candidate time.Duration, hasCandidate bool, attemptSkew time.Duration) error {
	if !clockSkewCodes[code] || !hasCandidate {
		return err
	}
	if difference := attemptSkew - candidate; difference > skewThreshold || -difference > skewThreshold {
		return &skewError{err}
	}
	return err
}

func (e *Engine) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

func (e *Engine) sleep(ctx context.Context, delay time.Duration) error {
	if e.Sleep != nil {
		return e.Sleep(ctx, delay)
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (e *Engine) send(ctx context.Context, request *http.Request, signingName, region string, signingTime time.Time) (int, http.Header, []byte, error) {
	if e.Credentials == nil {
		return 0, nil, nil, &credentialsError{errors.New("no credentials provider")}
	}
	credentials, err := e.Credentials.Retrieve(ctx)
	if err != nil {
		return 0, nil, nil, &credentialsError{err}
	}
	payload := []byte{}
	if request.Body != nil {
		payload, _ = io.ReadAll(request.Body)
		request.Body = io.NopCloser(bytes.NewReader(payload))
	}
	sum := sha256.Sum256(payload)
	// An engine built without New gets a signer per request: a shared one would
	// race between concurrent lookups.
	signer := e.signer
	if signer == nil {
		signer = v4.NewSigner()
	}
	if err := signer.SignHTTP(ctx, credentials, request, hex.EncodeToString(sum[:]), signingName, region, signingTime); err != nil {
		return 0, nil, nil, err
	}
	client := e.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	response, err := client.Do(request)
	if err != nil {
		return 0, nil, nil, err
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(response.Body, 16<<20))
	if err != nil {
		return 0, nil, nil, err
	}
	return response.StatusCode, response.Header, body, nil
}

func succeeded(spec Spec, body []byte, id string) Answer {
	tree, err := decode(spec, body)
	if err != nil {
		return Answer{Result: Unknown, Reason: TransportFailure}
	}
	if spec.Success.Mode != rules.SuccessSingular {
		for _, path := range spec.Success.Paths {
			if matches(tree, path, id) {
				return Answer{Result: Exists, Reason: "returned identifier matched"}
			}
		}
	}
	switch spec.Success.Mode {
	case rules.SuccessSingular, rules.SuccessEchoOrSingular:
		return Answer{Result: Exists, Reason: "singular lookup for this identifier succeeded"}
	default:
		return Answer{Result: Unknown, Reason: "successful response did not prove the requested identifier exists"}
	}
}

// errorCode reads the error code as each protocol carries it and normalises it
// as the SDK does. An error with no code has an empty code; the SDK calls it
// "UnknownError". decoded is false when a body is present but unreadable, which
// the SDK reports as a deserialization failure, not an AWS error.
func errorCode(spec Spec, status int, header http.Header, body []byte) (code string, decoded bool) {
	trimmed := bytes.TrimSpace(body)
	if code, decoded = protocolErrorCode(spec, header, body, trimmed); !decoded {
		return "", false
	}
	if code == "" && spec.NotFound.StatusCodeFallback && len(trimmed) == 0 {
		code = strings.ReplaceAll(http.StatusText(status), " ", "")
	}
	// Only the JSON and CBOR protocols strip namespaces and suffixes.
	if !xmlProtocol(spec.Protocol) {
		code = sanitizeCode(code)
	}
	return code, true
}

// protocolErrorCode reads the error code as the protocol's SDK deserializer
// does.
func protocolErrorCode(spec Spec, header http.Header, body, trimmed []byte) (string, bool) {
	switch spec.Protocol {
	case rules.AWSJSON10, rules.AWSJSON11, rules.RestJSON1:
		return jsonErrorCode(spec, header, body)
	case rules.RPCv2CBOR:
		// The SDK cannot read an empty CBOR error body.
		value, err := decodeCBOR(body)
		if err != nil {
			return "", false
		}
		fields, _ := value.(map[string]any)
		code, _ := fields["__type"].(string)
		return code, true
	case rules.AWSQuery, rules.EC2Query, rules.RestXML:
		if len(trimmed) > 0 {
			if _, err := decodeXML(body); err != nil && !errors.Is(err, errNoXMLRoot) {
				return "", false
			}
		}
		return xmlErrorCode(body), true
	}
	return "", true
}

func xmlProtocol(protocol string) bool {
	return protocol == rules.AWSQuery || protocol == rules.EC2Query || protocol == rules.RestXML
}

type credentialsError struct{ err error }

// Error returns the credentials failure message.
func (e *credentialsError) Error() string { return e.err.Error() }

// Unwrap returns the underlying credentials failure.
func (e *credentialsError) Unwrap() error { return e.err }

func contextReason(ctx context.Context) string {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return "inspection timed out"
	}
	return "inspection canceled"
}

// sanitizeCode strips a JSON or CBOR error code as the SDK does: from the first
// ":", then up to the first "#".
func sanitizeCode(code string) string {
	if index := strings.Index(code, ":"); index >= 0 {
		code = code[:index]
	}
	if index := strings.Index(code, "#"); index >= 0 {
		code = code[index+1:]
	}
	return code
}

// isType reports whether the client decodes code into the spec's modelled not-
// found type.
func isType(spec Spec, code string) bool {
	for _, typeCode := range spec.NotFound.TypeCodes {
		if code == typeCode || spec.Layout == "classic" && strings.EqualFold(code, typeCode) {
			return true
		}
	}
	return spec.NotFound.TypeNameMatches && code == spec.NotFound.Type
}
