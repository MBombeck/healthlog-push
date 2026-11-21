// Package admin is the operator command line. It talks to the running relay over its unix socket, so every
// command takes effect without a restart.
package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/MBombeck/healthlog-push/internal/relay"
)

// Usage is printed for "admin" without a command.
const Usage = `usage: healthlog-push admin <command> [args] [--flag value]

  stats                                   service state and usage aggregates (counts only)
  instance <id>                           tier, limits and binding counts of one instance
  suspects                                instances with invalid tokens, rebinds or challenges, worst first
  pause [--class all|alert|silent|liveactivity] [--tier all|probation] [--for 30m]
  resume                                  remove all pauses
  registration open|invite|closed
  invite                                  create a one-time registration code (7 days)
  notice set <id> [--level info|planned|action_required] [--for 72h]
  notice clear
  suspend <id> <reason>                   reasons: abuse spam invalid_tokens harassment legal compromised terms operator_request
  unsuspend <id>
  revoke <id> [reason]                    deletes all bindings of the instance
  block-token --token <hex> | --mac <hex>
  unblock-token --token <hex> | --mac <hex>
  limits <id> devices=<n>
  recovery --until YYYY-MM-DD [--from /export/registry.json]
  export                                  write /export/registry.json now
  breaker open|close|reset-apns
  status-file                             print the signed status document
`

// Parse turns command-line words into a request. "--k v" and "k=v" both become params.
func Parse(words []string) (*relay.AdminRequest, error) {
	if len(words) == 0 {
		return nil, errors.New("missing command")
	}
	ar := &relay.AdminRequest{Cmd: words[0], Params: map[string]string{}}
	for i := 1; i < len(words); i++ {
		w := words[i]
		switch {
		case strings.HasPrefix(w, "--"):
			k := strings.TrimPrefix(w, "--")
			if k2, v, ok := strings.Cut(k, "="); ok {
				ar.Params[k2] = v
				continue
			}
			if i+1 >= len(words) {
				return nil, fmt.Errorf("flag %s needs a value", w)
			}
			i++
			ar.Params[k] = words[i] //nolint:gosec // bounds checked above
		case strings.Contains(w, "="):
			k, v, _ := strings.Cut(w, "=")
			ar.Params[k] = v
		default:
			ar.Args = append(ar.Args, w)
		}
	}
	return ar, nil
}

// Run sends a request to the socket and writes the JSON answer to out.
func Run(socket string, ar *relay.AdminRequest, out io.Writer) error {
	c := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		},
	}}
	b, _ := json.Marshal(ar)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "http://admin/", bytes.NewReader(b))
	if err != nil {
		return err
	}
	resp, err := c.Do(req)
	if err != nil {
		return fmt.Errorf("relay not reachable on %s: %w", socket, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	var pretty bytes.Buffer
	if json.Indent(&pretty, body, "", "  ") == nil {
		body = pretty.Bytes()
	}
	_, _ = out.Write(append(bytes.TrimSpace(body), '\n'))
	if resp.StatusCode != http.StatusOK {
		return errors.New("command failed")
	}
	return nil
}
