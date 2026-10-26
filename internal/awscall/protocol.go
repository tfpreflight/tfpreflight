package awscall

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/tfpreflight/tfpreflight/rules"
)

// buildRequest builds the request for values, one per input member, against
// base, an endpoint URL whose path prefixes the operation's as the SDK joins
// them.
func buildRequest(ctx context.Context, spec Spec, base *url.URL, values map[string]string) (*http.Request, error) {
	parts, err := placeInputs(spec, values)
	if err != nil {
		return nil, err
	}
	body, err := parts.encodeBody(spec)
	if err != nil {
		return nil, err
	}
	parts.splitFixedQuery()
	return parts.request(ctx, spec, base, body)
}

type requestParts struct {
	path   string
	query  url.Values
	header http.Header
	fields map[string]any
	form   url.Values
}

func placeInputs(spec Spec, values map[string]string) (*requestParts, error) {
	parts := &requestParts{
		path:   spec.Path,
		query:  url.Values{},
		header: http.Header{},
		fields: map[string]any{},
		form:   url.Values{"Action": {spec.Operation}, "Version": {spec.APIVersion}},
	}
	if parts.path == "" {
		parts.path = "/"
	}
	for _, input := range spec.Inputs {
		v := values[input.Member]
		switch spec.Protocol {
		case rules.AWSJSON10, rules.AWSJSON11, rules.RPCv2CBOR:
			parts.fields[input.Name] = value(input, v)
		case rules.AWSQuery, rules.EC2Query:
			parts.form.Set(queryKey(input), v)
		case rules.RestJSON1, rules.RestXML:
			if err := parts.placeREST(spec, input, v); err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("unsupported protocol %q", spec.Protocol)
		}
	}
	return parts, nil
}

// queryKey is a query-protocol member name, with the first-element suffix a
// list member takes.
func queryKey(input rules.Input) string {
	key := input.Name
	if input.List {
		if input.ListMember != "" {
			key += "." + input.ListMember
		}
		key += ".1"
	}
	return key
}

func (parts *requestParts) placeREST(spec Spec, input rules.Input, v string) error {
	switch input.Location {
	case rules.InLabel:
		placeholder := "{" + input.Name + "}"
		if input.Greedy {
			placeholder = "{" + input.Name + "+}"
		}
		if !strings.Contains(parts.path, placeholder) {
			return fmt.Errorf("path %s has no label %s", parts.path, placeholder)
		}
		parts.path = strings.Replace(parts.path, placeholder, escapeLabel(v, input.Greedy), 1)
	case rules.InQuery:
		parts.query.Add(input.Name, v)
	case rules.InHeader:
		parts.header.Set(input.Name, v)
	case rules.InBody:
		if spec.Protocol == rules.RestXML {
			return errors.New("restXml body input is not supported")
		}
		parts.fields[input.Name] = value(input, v)
	default:
		return fmt.Errorf("unknown input location %q", input.Location)
	}
	return nil
}

// encodeBody serialises the body and sets the protocol's headers. RPCv2CBOR also
// fixes the path.
func (parts *requestParts) encodeBody(spec Spec) ([]byte, error) {
	switch spec.Protocol {
	case rules.AWSJSON10, rules.AWSJSON11:
		parts.header.Set("Content-Type", "application/x-amz-json-"+strings.TrimPrefix(strings.ReplaceAll(spec.Protocol, "_", "."), "awsJson"))
		parts.header.Set("X-Amz-Target", spec.Target)
		return json.Marshal(parts.fields)
	case rules.RPCv2CBOR:
		parts.path = "/service/" + spec.Target + "/operation/" + spec.Operation
		parts.header.Set("Smithy-Protocol", "rpc-v2-cbor")
		parts.header.Set("Content-Type", "application/cbor")
		parts.header.Set("Accept", "application/cbor")
		return encodeCBOR(parts.fields), nil
	case rules.AWSQuery, rules.EC2Query:
		parts.header.Set("Content-Type", "application/x-www-form-urlencoded")
		return []byte(parts.form.Encode()), nil
	case rules.RestJSON1:
		if len(parts.fields) > 0 {
			parts.header.Set("Content-Type", "application/json")
			return json.Marshal(parts.fields)
		}
	}
	return nil, nil
}

// splitFixedQuery moves a query fixed in the path template, as in
// /2020-05-31/distribution/{Id}?x=y, into the request query.
func (parts *requestParts) splitFixedQuery() {
	before, after, found := strings.Cut(parts.path, "?")
	if !found {
		return
	}
	parts.path = before
	fixed, _ := url.ParseQuery(after)
	for key, values := range fixed {
		for _, v := range values {
			parts.query.Add(key, v)
		}
	}
}

func (parts *requestParts) request(ctx context.Context, spec Spec, base *url.URL, body []byte) (*http.Request, error) {
	target := url.URL{Scheme: base.Scheme, Host: base.Host, Path: joinPath(base.Path, unescapedPath(parts.path)), RawPath: joinPath(base.Path, parts.path), RawQuery: parts.query.Encode()}
	method := spec.Method
	if method == "" {
		method = http.MethodPost
	}
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	request, err := http.NewRequestWithContext(ctx, method, target.String(), reader)
	if err != nil {
		return nil, err
	}
	for key, values := range parts.header {
		request.Header[key] = values
	}
	for key, value := range spec.Headers {
		request.Header.Set(key, value)
	}
	if body != nil {
		request.ContentLength = int64(len(body))
	}
	return request, nil
}

func value(input rules.Input, id string) any {
	if input.List {
		return []string{id}
	}
	return id
}

// escapeLabel percent-encodes a URI label as Smithy does: everything but the
// unreserved characters, and "/" too unless the label is greedy.
func escapeLabel(value string, greedy bool) string {
	var b strings.Builder
	for _, c := range []byte(value) {
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_', c == '.', c == '~':
			b.WriteByte(c)
		case c == '/' && greedy:
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

func unescapedPath(raw string) string {
	path, err := url.PathUnescape(raw)
	if err != nil {
		return raw
	}
	return path
}

type element struct {
	Name     string
	Text     string
	Children []*element
}

// decode turns a response body into a tree the path matcher can walk. The query
// protocols wrap their result, and the start node skips that wrapper.
func decode(spec Spec, body []byte) (any, error) {
	switch spec.Protocol {
	case rules.AWSJSON10, rules.AWSJSON11, rules.RestJSON1:
		return decodeJSONOutput(spec.Layout, body)
	case rules.RPCv2CBOR:
		if len(body) == 0 {
			return nil, nil
		}
		value, err := decodeCBOR(body)
		if err != nil {
			return nil, err
		}
		if _, ok := value.(map[string]any); !ok {
			return nil, errors.New("CBOR output is not a map")
		}
		return value, nil
	case rules.AWSQuery, rules.EC2Query, rules.RestXML:
		root, err := decodeXML(body)
		if errors.Is(err, errNoXMLRoot) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		if spec.Protocol == rules.AWSQuery {
			for _, child := range root.Children {
				if strings.EqualFold(child.Name, spec.Operation+"Result") {
					return child, nil
				}
			}
			return &element{}, nil
		}
		return root, nil
	}
	return nil, fmt.Errorf("unsupported protocol %q", spec.Protocol)
}

func decodeXML(body []byte) (*element, error) {
	decoder := xml.NewDecoder(bytes.NewReader(body))
	var stack []*element
	var root *element
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		switch t := token.(type) {
		case xml.StartElement:
			node := &element{Name: t.Name.Local}
			switch {
			case len(stack) > 0:
				parent := stack[len(stack)-1]
				parent.Children = append(parent.Children, node)
			case root == nil:
				root = node
			default:
				return nil, errors.New("more than one root element")
			}
			stack = append(stack, node)
		case xml.EndElement:
			if len(stack) == 0 {
				return nil, errors.New("unbalanced XML")
			}
			stack = stack[:len(stack)-1]
		case xml.CharData:
			if len(stack) > 0 {
				stack[len(stack)-1].Text += string(t)
			}
		}
	}
	if root == nil && len(stack) == 0 {
		return nil, errNoXMLRoot
	}
	if len(stack) != 0 {
		return nil, errors.New("incomplete XML document")
	}
	return root, nil
}

// errNoXMLRoot is a body with no element at all. The SDK reads it as an empty
// response, not a malformed one.
var errNoXMLRoot = errors.New("no XML root element")

// matches reports whether any value at path equals id. Lists are traversed:
// JSON and CBOR arrays implicitly, XML through repeated elements.
func matches(tree any, path []string, id string) bool {
	if tree == nil || len(path) == 0 {
		return false
	}
	nodes := []any{tree}
	for _, step := range path {
		var next []any
		for _, node := range nodes {
			next = append(next, children(node, step)...)
		}
		if len(next) == 0 {
			return false
		}
		nodes = next
	}
	for _, node := range nodes {
		if holdsID(node, id) {
			return true
		}
	}
	return false
}

// holdsID reports whether a node the path reached is the identifier: a
// string, a text-only XML element, or a list containing the string.
func holdsID(node any, id string) bool {
	switch v := node.(type) {
	case string:
		return v == id
	case *element:
		return len(v.Children) == 0 && strings.TrimSpace(v.Text) == id
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok && s == id {
				return true
			}
		}
	}
	return false
}

func children(node any, step string) []any {
	switch v := node.(type) {
	case map[string]any:
		child, ok := v[step]
		if !ok {
			return nil
		}
		if list, isList := child.([]any); isList {
			// A list of scalars stays whole so the leaf comparison can scan
			// it; a list of objects is traversed item by item.
			if len(list) > 0 && isString(list[0]) {
				return []any{list}
			}
			return list
		}
		return []any{child}
	case []any:
		var out []any
		for _, item := range v {
			out = append(out, children(item, step)...)
		}
		return out
	case *element:
		// The SDK matches XML element names without regard to case.
		var out []any
		for _, child := range v.Children {
			if strings.EqualFold(child.Name, step) {
				out = append(out, child)
			}
		}
		return out
	}
	return nil
}

func isString(value any) bool {
	_, ok := value.(string)
	return ok
}

// decodeJSONOutput reads a successful JSON body as the client's layout does.
// Both read only the first JSON value and need an object. The classic
// layout also accepts no value at all, or null, as an empty output; the
// schema layout accepts only a body with no bytes.
func decodeJSONOutput(layout string, body []byte) (any, error) {
	if layout == "schema" && len(body) == 0 {
		return nil, nil
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var value any
	err := decoder.Decode(&value)
	if err == io.EOF && layout != "schema" {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if value == nil {
		if layout == "schema" {
			return nil, errors.New("JSON output is null")
		}
		return nil, nil
	}
	if _, ok := value.(map[string]any); !ok {
		return nil, errors.New("JSON output is not an object")
	}
	return value, nil
}

// jsonErrorCode reads a JSON error's code as the client does: the first
// JSON value decoded into the client's own error-info shape, the
// X-Amzn-ErrorType header first. Classic restJson1 clients prefer a string
// "code" member to "__type"; every other JSON client prefers "__type" and
// accepts a "code" of any type. decoded is false when the body does not fit
// the shape, which the client reports as a deserialization failure.
func jsonErrorCode(spec Spec, header http.Header, body []byte) (code string, decoded bool) {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	code = header.Get("X-Amzn-ErrorType")
	if spec.Layout == "classic" && spec.Protocol == rules.RestJSON1 {
		var info struct {
			Code    string
			Type    string `json:"__type"`
			Message string
		}
		if err := decoder.Decode(&info); err != nil && err != io.EOF {
			return "", false
		}
		return firstNonEmpty(code, info.Code, info.Type), true
	}
	var info struct {
		Type    string `json:"__type"`
		Message string
		Code    any
	}
	if err := decoder.Decode(&info); err != nil && err != io.EOF {
		return "", false
	}
	text, _ := info.Code.(string)
	return firstNonEmpty(code, info.Type, text), true
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

// xmlErrorCode finds <Code> inside <Error>, which is where every XML protocol
// puts it: <ErrorResponse><Error>, <Response><Errors><Error>, or a bare <Error>.
func xmlErrorCode(body []byte) string {
	root, err := decodeXML(body)
	if err != nil {
		return ""
	}
	var find func(*element, bool) string
	find = func(node *element, inError bool) string {
		if inError && node.Name == "Code" && len(node.Children) == 0 {
			return strings.TrimSpace(node.Text)
		}
		for _, child := range node.Children {
			if code := find(child, inError || node.Name == "Error"); code != "" {
				return code
			}
		}
		return ""
	}
	return find(root, root.Name == "Error")
}

// joinPath joins an endpoint path and an operation path exactly as smithy's
// JoinPath does.
func joinPath(a, b string) string {
	if len(a) == 0 {
		a = "/"
	} else if a[0] != '/' {
		a = "/" + a
	}
	if len(b) != 0 && b[0] == '/' {
		b = b[1:]
	}
	if len(b) != 0 && len(a) > 1 && a[len(a)-1] != '/' {
		a += "/"
	}
	return a + b
}

// requestID is the request ID AWS sent: a header for the JSON, CBOR and REST
// protocols, the response body for the query protocols.
func requestID(spec Spec, header http.Header, body []byte) string {
	for _, key := range []string{"X-Amzn-Requestid", "X-Amz-Request-Id"} {
		if id := header.Get(key); id != "" {
			return id
		}
	}
	switch spec.Protocol {
	case rules.AWSQuery, rules.EC2Query, rules.RestXML:
		if root, err := decodeXML(body); err == nil {
			return xmlText(root, func(name string) bool { return strings.EqualFold(name, "RequestId") })
		}
	}
	return ""
}

func errorMessage(spec Spec, body []byte) string {
	switch spec.Protocol {
	case rules.AWSJSON10, rules.AWSJSON11, rules.RestJSON1:
		var info struct{ Message string }
		decoder := json.NewDecoder(bytes.NewReader(body))
		if decoder.Decode(&info) == nil {
			return info.Message
		}
	case rules.RPCv2CBOR:
		return cborMessage(body)
	case rules.AWSQuery, rules.EC2Query, rules.RestXML:
		if root, err := decodeXML(body); err == nil {
			return xmlText(root, func(name string) bool { return name == "Message" })
		}
	}
	return ""
}

// cborMessage is the message of a CBOR error body, under either spelling of its
// key.
func cborMessage(body []byte) string {
	value, err := decodeCBOR(body)
	if err != nil {
		return ""
	}
	fields, _ := value.(map[string]any)
	for _, key := range []string{"message", "Message"} {
		if text, ok := fields[key].(string); ok {
			return text
		}
	}
	return ""
}

func xmlText(node *element, match func(string) bool) string {
	if match(node.Name) && len(node.Children) == 0 {
		return strings.TrimSpace(node.Text)
	}
	for _, child := range node.Children {
		if text := xmlText(child, match); text != "" {
			return text
		}
	}
	return ""
}
