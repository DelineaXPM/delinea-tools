package secrets

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"

	"github.com/DelineaXPM/delinea-tools/api"
)

const maxSecretResponseBytes = 32 << 20

// errTooLarge marks a fetch that exceeded a size bound — one response over
// maxSecretResponseBytes, or a secret whose attachment fan-out breaks the
// attachment caps. Accepting the read would silently truncate the secret;
// another attempt would fetch the same bytes, so diagnose treats it as
// permanent.
var errTooLarge = errors.New("response too large")

// errBadResponse marks a 2xx response whose body is not the JSON the API
// produces — a captive portal or a URL that is not a vault, not a network
// failure; another attempt would fetch the same bytes, so diagnose treats it
// as permanent.
var errBadResponse = errors.New("response is not a secret")

// A secret's file attachments are downloaded eagerly and held in memory. These
// bound the fan-out so a hostile or compromised vault cannot turn one secret
// response into unbounded downloads or resident memory: at most this many
// attachments, and at most this many bytes across all of them per secret.
const (
	maxAttachments      = 64
	maxAttachmentsBytes = 64 << 20
)

// apiFetcher implements Fetcher on the api engine. For a platform target the
// calls are routed to the tenant's vault. File-attachment fields are
// downloaded and substituted for their placeholder ItemValue, so callers see
// the content transparently.
type apiFetcher struct {
	c     *api.Client
	vault bool
}

func (f *apiFetcher) CloseIdleConnections() { f.c.CloseIdleConnections() }

// String renders through the api.Client's redaction so secrets.Client can log a
// safe summary without exposing the credentials the underlying Config holds.
func (f *apiFetcher) String() string { return f.c.String() }

func (f *apiFetcher) Secret(ctx context.Context, id int) (*Secret, error) {
	return f.fetch(ctx, "/api/v1/secrets/"+strconv.Itoa(id), id)
}

func (f *apiFetcher) SecretByPath(ctx context.Context, path string) (*Secret, error) {
	return f.fetch(ctx, "/api/v1/secrets/0?secretPath="+url.QueryEscape(path), 0)
}

func (f *apiFetcher) fetch(ctx context.Context, path string, expectedID int) (*Secret, error) {
	data, err := f.get(ctx, path)
	if err != nil {
		return nil, err
	}
	var s Secret
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("%w: parsing it: %v (does the URL point at a Secret Server or vault API?)", errBadResponse, err)
	}
	if s.ID <= 0 {
		return nil, fmt.Errorf("%w: secret response has invalid id %d", errBadResponse, s.ID)
	}
	if expectedID > 0 && s.ID != expectedID {
		return nil, fmt.Errorf("%w: requested secret %d but the response identified secret %d", errBadResponse, expectedID, s.ID)
	}
	downloaded, total := 0, 0
	for i, fld := range s.Fields {
		if !(fld.IsFile && fld.FileAttachmentID != 0 && fld.Filename != "") {
			continue
		}
		// PathEscape deliberately leaves dot segments unchanged. Reject them
		// before URL resolution can normalize the attachment request outside the
		// fields endpoint; an empty slug is not a valid field segment either.
		if fld.Slug == "" || fld.Slug == "." || fld.Slug == ".." {
			return nil, fmt.Errorf("%w: secret %d has a file attachment with an invalid field slug", errBadResponse, s.ID)
		}
		if downloaded++; downloaded > maxAttachments {
			return nil, fmt.Errorf("%w: secret %d has more than %d file attachments; refusing to download further", errTooLarge, s.ID, maxAttachments)
		}
		// The slug comes from the server's own JSON, so escape it into the path
		// segment rather than trusting it not to carry "?" or "/".
		content, err := f.get(ctx, fmt.Sprintf("/api/v1/secrets/%d/fields/%s", s.ID, url.PathEscape(fld.Slug)))
		if err != nil {
			return nil, err
		}
		if total += len(content); total > maxAttachmentsBytes {
			return nil, fmt.Errorf("%w: secret %d file attachments exceed %d bytes in total; refusing more", errTooLarge, s.ID, maxAttachmentsBytes)
		}
		s.Fields[i].ItemValue = string(content)
	}
	return &s, nil
}

// get fetches path through the engine's buffered call, which retries
// transport failures, transient statuses (with Retry-After), and a body read
// that dies after the headers on one budget — so this layer adds no retry
// loop of its own that would compound with it. The cap is read one byte over
// so an over-length response is rejected rather than silently truncated.
func (f *apiFetcher) get(ctx context.Context, path string) ([]byte, error) {
	resp, err := f.c.DoBufferedResponse(ctx, api.Request{
		Method:   http.MethodGet,
		Path:     path,
		UseVault: f.vault,
	}, maxSecretResponseBytes+1)
	if err != nil {
		return nil, err
	}
	status, body := resp.StatusCode, resp.Body
	if status < 200 || status > 299 {
		// The status leads the message so diagnose can read the code off the
		// front; the body often carries the only cause Delinea names.
		return nil, fmt.Errorf("%d %s: %s", status, http.StatusText(status), resp.DiagnosticSnippet())
	}
	if len(body) > maxSecretResponseBytes {
		return nil, fmt.Errorf("%w: %s returned more than %d bytes", errTooLarge, path, maxSecretResponseBytes)
	}
	return body, nil
}
