package edge

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Model aliases let an edge administrator reconcile the model names agents
// ask for with the names the configured provider accepts, without touching
// every harness: e.g. a Hermes config that requests "deepseek-v4-flash"
// while the provider serves "deepseek-flash" (found in a live Hermes run,
// where the raw name got a 400 from the provider).
//
//	DESCLES_MODEL_ALIASES="deepseek-v4-flash=deepseek-flash,claude-sonnet-4-5=deepseek-v4-pro"

// ParseModelAliases reads "from=to,from2=to2".
func ParseModelAliases(spec string) (map[string]string, error) {
	out := map[string]string{}
	for _, pair := range strings.Split(spec, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		from, to, ok := strings.Cut(pair, "=")
		from, to = strings.TrimSpace(from), strings.TrimSpace(to)
		if !ok || from == "" || to == "" || from == to {
			return nil, fmt.Errorf("model alias %q: use from=to", pair)
		}
		if _, dup := out[from]; dup {
			return nil, fmt.Errorf("model alias for %q given twice", from)
		}
		out[from] = to
	}
	for from, to := range out {
		if _, chained := out[to]; chained {
			return nil, fmt.Errorf("model alias %s=%s chains into another alias; map directly", from, to)
		}
	}
	return out, nil
}

const aliasMaxBody = 64 << 20

// AliasModels rewrites the "model" field of JSON request bodies before the
// model gateway routes, prices and records them, so everything downstream
// sees the name the provider accepts. Bodies it cannot parse, or larger than
// 64 MiB, pass through unchanged.
func AliasModels(aliases map[string]string, next http.Handler) http.Handler {
	if len(aliases) == 0 {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Body == nil {
			next.ServeHTTP(w, r)
			return
		}
		head, err := io.ReadAll(io.LimitReader(r.Body, aliasMaxBody+1))
		if err != nil {
			http.Error(w, "could not read request body", http.StatusBadRequest)
			return
		}
		if len(head) > aliasMaxBody {
			r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(head), r.Body))
			next.ServeHTTP(w, r)
			return
		}
		body := head
		var fields map[string]json.RawMessage
		if json.Unmarshal(head, &fields) == nil {
			var model string
			if raw, ok := fields["model"]; ok && json.Unmarshal(raw, &model) == nil {
				if to, ok := aliases[model]; ok {
					fields["model"], _ = json.Marshal(to)
					if rewritten, err := json.Marshal(fields); err == nil {
						body = rewritten
						r.Header.Set("X-Descles-Requested-Model", model)
					}
				}
			}
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
		next.ServeHTTP(w, r)
	})
}
