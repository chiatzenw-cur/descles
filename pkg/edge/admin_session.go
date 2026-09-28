package edge

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const consoleSessionCookie = "descles_console_session"
const rememberedSession = 30 * 24 * time.Hour
const browserSession = 12 * time.Hour

var errCrossOrigin = errors.New("cross-origin browser request")

func (a *ApprovalAdmin) resolveToken(token string) (AdminIdentity, bool) {
	if token != "" && subtle.ConstantTimeCompare([]byte(token), []byte(a.Token)) == 1 {
		return AdminIdentity{ID: "owner", Name: "Bootstrap owner token", Role: "owner", Shared: true}, true
	}
	if a.Access == nil {
		return AdminIdentity{}, false
	}
	return a.Access.Resolve(token)
}

func tokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func (a *ApprovalAdmin) sessionKey() [32]byte {
	return sha256.Sum256([]byte("descles console session v1:" + a.Token))
}

func (a *ApprovalAdmin) signedSession(digest string, expires time.Time) string {
	payload := digest + ":" + strconv.FormatInt(expires.Unix(), 10)
	key := a.sessionKey()
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." + hex.EncodeToString(mac.Sum(nil))
}

func (a *ApprovalAdmin) resolveSession(raw string) (AdminIdentity, bool) {
	parts := strings.Split(raw, ".")
	if len(parts) != 2 || len(raw) > 256 {
		return AdminIdentity{}, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return AdminIdentity{}, false
	}
	signature, err := hex.DecodeString(parts[1])
	if err != nil || len(signature) != sha256.Size {
		return AdminIdentity{}, false
	}
	key := a.sessionKey()
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write(payload)
	if !hmac.Equal(signature, mac.Sum(nil)) {
		return AdminIdentity{}, false
	}
	fields := strings.Split(string(payload), ":")
	if len(fields) != 2 || len(fields[0]) != sha256.Size*2 {
		return AdminIdentity{}, false
	}
	expires, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil || time.Now().Unix() >= expires || expires > time.Now().Add(rememberedSession).Unix()+60 {
		return AdminIdentity{}, false
	}
	if subtle.ConstantTimeCompare([]byte(fields[0]), []byte(tokenHash(a.Token))) == 1 {
		return AdminIdentity{ID: "owner", Name: "Bootstrap owner token", Role: "owner", Shared: true}, true
	}
	if a.Access == nil {
		return AdminIdentity{}, false
	}
	return a.Access.ResolveDigest(fields[0])
}

func loopbackRequest(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func browserHTTPS(r *http.Request) bool {
	return r.TLS != nil || (loopbackRequest(r) && strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https"))
}

func browserTransportAllowed(r *http.Request) bool {
	if browserHTTPS(r) {
		return true
	}
	if !loopbackRequest(r) {
		return false
	}
	host := r.Host
	if parsed, _, err := net.SplitHostPort(host); err == nil {
		host = parsed
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

func sameConsoleOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return false
	}
	u, err := url.Parse(origin)
	if err != nil || !strings.EqualFold(u.Host, r.Host) {
		return false
	}
	scheme := "http"
	if browserHTTPS(r) {
		scheme = "https"
	}
	return u.Scheme == scheme && u.User == nil && u.RawQuery == "" && u.Fragment == "" && u.Path == ""
}

func (a *ApprovalAdmin) createSession(w http.ResponseWriter, r *http.Request) {
	if !browserTransportAllowed(r) {
		http.Error(w, "browser sign-in requires HTTPS or a local edge", http.StatusForbidden)
		return
	}
	if origin := r.Header.Get("Origin"); origin != "" && !sameConsoleOrigin(r) {
		http.Error(w, "same-origin sign-in required", http.StatusForbidden)
		return
	}
	var in struct {
		Token    string `json:"token"`
		Remember bool   `json:"remember"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&in); err != nil || strings.TrimSpace(in.Token) == "" {
		http.Error(w, "console token required", http.StatusBadRequest)
		return
	}
	id, ok := a.resolveToken(strings.TrimSpace(in.Token))
	if !ok {
		http.Error(w, "console token rejected", http.StatusUnauthorized)
		return
	}
	duration := browserSession
	if in.Remember {
		duration = rememberedSession
	}
	cookie := &http.Cookie{Name: consoleSessionCookie, Value: a.signedSession(tokenHash(strings.TrimSpace(in.Token)), time.Now().Add(duration)), Path: "/admin", HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: browserHTTPS(r)}
	if in.Remember {
		cookie.MaxAge = int(duration.Seconds())
	}
	http.SetCookie(w, cookie)
	w.Header().Set("Cache-Control", "no-store")
	writeJSONBody(w, id)
}

func (a *ApprovalAdmin) deleteSession(w http.ResponseWriter, r *http.Request) {
	if !sameConsoleOrigin(r) {
		http.Error(w, "same-origin sign-out required", http.StatusForbidden)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: consoleSessionCookie, Value: "", Path: "/admin", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: browserHTTPS(r)})
	w.Header().Set("Cache-Control", "no-store")
	writeJSONBody(w, map[string]any{"signed_out": true})
}

func (a *ApprovalAdmin) sessionIdentity(r *http.Request) (AdminIdentity, error) {
	if header := r.Header.Get("Authorization"); header != "" {
		if !strings.HasPrefix(header, "Bearer ") {
			return AdminIdentity{}, errors.New("invalid authorization header")
		}
		if id, ok := a.resolveToken(strings.TrimSpace(strings.TrimPrefix(header, "Bearer "))); ok {
			return id, nil
		}
		return AdminIdentity{}, errors.New("invalid token")
	}
	cookie, err := r.Cookie(consoleSessionCookie)
	if err != nil {
		return AdminIdentity{}, err
	}
	if !browserTransportAllowed(r) {
		return AdminIdentity{}, errors.New("insecure browser transport")
	}
	id, ok := a.resolveSession(cookie.Value)
	if !ok {
		return AdminIdentity{}, errors.New("invalid browser session")
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead && !sameConsoleOrigin(r) {
		return AdminIdentity{}, errCrossOrigin
	}
	return id, nil
}
