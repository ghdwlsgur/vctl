// Package gitlabapi is the sliver of the GitLab API vctl uses: reading and
// committing one repository file. It exists so a DNS change lands in the IaC
// repo as a commit — the repo is the source of truth an ArgoCD sync would
// reassert, so a write that skipped it would be undone by the next sync.
//
// Hand-rolled over net/http like internal/openstackapi and internal/kubeapi;
// the token is read from Vault by the caller at use time.
package gitlabapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ghdwlsgur/vctl/internal/httpc"
)

// ErrConflict is the optimistic-concurrency refusal: the file was committed
// to between the read and the write. The caller re-reads and reapplies.
var ErrConflict = errors.New("the file changed since it was read")

// Client is a session against one GitLab, as one token.
type Client struct {
	base  string
	token string
	http  *http.Client
}

// New builds a client for base (e.g. https://gitlab.sre.local), trusting
// caPEM when given and the system roots otherwise.
func New(base, token string, caPEM []byte) (*Client, error) {
	if base == "" || token == "" {
		return nil, fmt.Errorf("gitlab base url and token are both required")
	}
	hc, err := httpc.NewClient(20*time.Second, httpc.TLS{CAPEM: caPEM})
	if err != nil {
		return nil, fmt.Errorf("gitlab CA: %w", err)
	}
	// Go strips Authorization on a cross-host redirect but not custom headers,
	// so a redirect to another host would carry PRIVATE-TOKEN with it. This
	// client only ever talks to one GitLab; refuse a redirect that leaves its
	// host rather than hand the token away.
	hc.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if req.URL.Host != via[0].URL.Host {
			return fmt.Errorf("refusing cross-host redirect to %s", req.URL.Host)
		}
		if len(via) >= 10 {
			return fmt.Errorf("stopped after 10 redirects")
		}
		return nil
	}
	return &Client{base: strings.TrimRight(base, "/"), token: token, http: hc}, nil
}

// File is one repository file at one ref: its content and the commit to name
// when writing it back.
type File struct {
	Content      string
	LastCommitID string
}

func (c *Client) fileURL(project, path, ref string) string {
	u := fmt.Sprintf("%s/api/v4/projects/%s/repository/files/%s",
		c.base, url.PathEscape(project), url.PathEscape(path))
	if ref != "" {
		u += "?ref=" + url.QueryEscape(ref)
	}
	return u
}

// GetFile reads one file at a ref.
func (c *Client) GetFile(ctx context.Context, project, path, ref string) (*File, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.fileURL(project, path, ref), nil)
	if err != nil {
		return nil, err
	}
	var out struct {
		Content      string `json:"content"`
		Encoding     string `json:"encoding"`
		LastCommitID string `json:"last_commit_id"`
	}
	if err := c.do(req, &out); err != nil {
		return nil, err
	}
	content := out.Content
	if out.Encoding == "base64" {
		raw, err := base64.StdEncoding.DecodeString(out.Content)
		if err != nil {
			return nil, fmt.Errorf("decode %s: %w", path, err)
		}
		content = string(raw)
	}
	return &File{Content: content, LastCommitID: out.LastCommitID}, nil
}

// UpdateFile commits new content for one file on a branch. lastCommitID is
// the precondition: GitLab refuses the write when the file has moved past it,
// which surfaces here as ErrConflict.
func (c *Client) UpdateFile(ctx context.Context, project, path, branch, content, message, lastCommitID string) error {
	body, err := json.Marshal(map[string]string{
		"branch":         branch,
		"content":        content,
		"commit_message": message,
		"last_commit_id": lastCommitID,
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, c.fileURL(project, path, ""), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	return c.do(req, nil)
}

func (c *Client) do(req *http.Request, into any) error {
	req.Header.Set("PRIVATE-TOKEN", c.token)
	resp, err := httpc.Do(c.http, req, 8<<20)
	if err != nil {
		return err
	}
	// GitLab answers a stale last_commit_id with 400 and this sentence rather
	// than a 409; both mean the same race.
	if resp.Status == http.StatusConflict ||
		(resp.Status == http.StatusBadRequest && bytes.Contains(resp.Body, []byte("You are attempting to update a file that has changed"))) {
		return fmt.Errorf("%s: %w", req.URL.Path, ErrConflict)
	}
	if !resp.OK() {
		return fmt.Errorf("%s: %s: %s", req.URL.Path, resp.StatusText, httpc.Snippet(resp.Body, 300))
	}
	if into == nil {
		return nil
	}
	return resp.JSON(into)
}
