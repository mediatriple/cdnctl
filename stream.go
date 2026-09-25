package main

// Streaming requests for folder transfers (tree, tar, tar-apply).
//
// doRequest reads the whole answer into memory under a 120 s total timeout. That
// is right for small JSON answers and wrong for a folder: a 2 GB wp-content tar
// takes longer than any fixed total, and holding it in memory is not an option.
// A stream instead gets 120 s for the response headers and then an idle
// watchdog: it is aborted only when no byte arrives for 120 s. The edge in front
// of the panel drops a connection after 60 s of silence (proxy_read_timeout), so
// the server side sends data or a heartbeat long before this fires; the watchdog
// is for a connection that died without anyone saying so.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"sync"
	"time"
)

var (
	streamHeaderTimeout = 120 * time.Second
	streamIdleTimeout   = 120 * time.Second
)

// maxStreamAnswer bounds a JSON answer read from a stream. tar-apply caps its
// path lists at 200 entries each, and heartbeats are one space per 15 s.
const maxStreamAnswer = 4 << 20

func streamClient() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.ResponseHeaderTimeout = streamHeaderTimeout
	return &http.Client{Transport: transport} // no Timeout: the idle watchdog replaces it
}

// idleReader aborts the request when no byte has arrived for d.
type idleReader struct {
	body   io.ReadCloser
	d      time.Duration
	cancel context.CancelFunc
	timer  *time.Timer

	mu    sync.Mutex
	fired bool
}

func newIdleReader(body io.ReadCloser, d time.Duration, cancel context.CancelFunc) *idleReader {
	r := &idleReader{body: body, d: d, cancel: cancel}
	r.timer = time.AfterFunc(d, func() {
		r.mu.Lock()
		r.fired = true
		r.mu.Unlock()
		cancel()
	})
	return r
}

func (r *idleReader) Read(p []byte) (int, error) {
	n, err := r.body.Read(p)
	if n > 0 {
		r.timer.Reset(r.d)
	}
	if err != nil && err != io.EOF {
		r.mu.Lock()
		fired := r.fired
		r.mu.Unlock()
		if fired {
			return n, fmt.Errorf("no data from the server for %s; the connection stalled", r.d)
		}
	}
	return n, err
}

func (r *idleReader) Close() error {
	r.timer.Stop()
	err := r.body.Close()
	r.cancel()
	return err
}

func isJSONContentType(value string) bool {
	mediaType, _, err := mime.ParseMediaType(value)
	return err == nil && (mediaType == "application/json" || mediaType == "application/problem+json")
}

// requestStream POSTs a JSON payload with the same token and endpoint rules as
// requestJSON. A 2xx answer that is not JSON comes back as a body to read (the
// caller closes it). Anything else — an error status or a JSON document — comes
// back decoded, with _http_status set, exactly like doRequest; a network failure
// before the headers is reported the same way doRequest reports it.
func requestStream(path string, payload map[string]any) (io.ReadCloser, map[string]any, error) {
	cfg := readConfig()
	if cfg.Token == "" {
		return nil, nil, errExitMessage(2, "Missing token. Run: cdnctl login (opens a browser; add --password-login for email+password)")
	}
	data, err := json.Marshal(payloadOrEmpty(payload))
	if err != nil {
		return nil, nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint(cfg, path), bytes.NewReader(data))
	if err != nil {
		cancel()
		return nil, nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+cfg.Token)
	resp, err := streamClient().Do(req)
	if err != nil {
		cancel()
		return nil, map[string]any{"status": false, "http_status": 0, "error": err.Error()}, nil
	}
	body := newIdleReader(resp.Body, streamIdleTimeout, cancel)
	if resp.StatusCode >= 200 && resp.StatusCode < 300 && !isJSONContentType(resp.Header.Get("Content-Type")) {
		return body, nil, nil
	}
	defer body.Close()
	decoded, err := decodeStreamAnswer(body)
	if err != nil {
		return nil, nil, err
	}
	decoded["_http_status"] = resp.StatusCode
	return nil, decoded, nil
}

// requestStreamJSON is requestStream for calls whose answer is always JSON
// (tar-apply): leading heartbeat spaces are skipped by the JSON decoder.
func requestStreamJSON(path string, payload map[string]any) (map[string]any, error) {
	body, decoded, err := requestStream(path, payload)
	if err != nil || decoded != nil {
		return decoded, err
	}
	defer body.Close()
	decoded, err = decodeStreamAnswer(body)
	if err != nil {
		return nil, err
	}
	decoded["_http_status"] = http.StatusOK
	return decoded, nil
}

func decodeStreamAnswer(body io.Reader) (map[string]any, error) {
	// tar-apply keeps the connection alive with 8 KiB of spaces every 15 s
	// before its JSON; an hour-long apply sends ~2 MiB of them. Skip that
	// whitespace so only the JSON itself counts against the cap.
	br := bufio.NewReader(body)
	for {
		b, err := br.ReadByte()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("reading the server's answer failed: %w", err)
		}
		if b != ' ' && b != '\n' && b != '\r' && b != '\t' {
			_ = br.UnreadByte()
			break
		}
	}
	raw, err := io.ReadAll(io.LimitReader(br, maxStreamAnswer))
	if err != nil {
		return nil, fmt.Errorf("reading the server's answer failed: %w", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil || decoded == nil {
		decoded = map[string]any{"raw_body": string(bytes.TrimSpace(raw))}
	}
	return decoded, nil
}

// streamUnsupported reports an answer that means "this server cannot do folder
// transfers": the account's pod has no GNU tar (tool_missing), or the panel
// predates the route (a plain 404/405 without an error_code — a missing folder
// is a 404 too, but it always carries file_not_found).
func streamUnsupported(resp map[string]any) bool {
	code := strval(resp["error_code"])
	if code == "tool_missing" {
		return true
	}
	status := httpStatusOf(resp)
	return code == "" && (status == http.StatusNotFound || status == http.StatusMethodNotAllowed)
}
