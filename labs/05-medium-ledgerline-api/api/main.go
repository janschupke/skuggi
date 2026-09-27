// Ledgerline API — DELIBERATELY VULNERABLE Go practice target.
//
// The vulnerabilities are logic flaws, not scanner-visible injections:
//   - mass assignment: POST /v1/customers honours a client-supplied "role".
//   - broken access control via undiscoverable routes: the admin endpoints are
//     only named in a leaked OpenAPI doc at a non-obvious path (referenced by
//     the JS bundle), not in any default wordlist.
//   - TOCTOU race: POST /v1/transfer checks then debits with a gap, so
//     concurrent requests double-spend.
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const jwtSecret = "ledgerline-session-hs256-do-not-share"

type user struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

type account struct {
	ID      string `json:"id"`
	Owner   string `json:"owner"`
	Balance int    `json:"balance"`
}

type contract struct {
	ID           string `json:"id"`
	Counterparty string `json:"counterparty"`
	Amount       int    `json:"amount"`
	Signature    string `json:"signature"`
}

type seed struct {
	SigningKey string     `json:"signing_key"`
	Users      []user     `json:"users"`
	Accounts   []account  `json:"accounts"`
	Contracts  []contract `json:"contracts"`
}

var (
	mu    sync.Mutex
	users = map[string]user{}
	accts = map[string]*account{}
	data  seed
)

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func sign(input string) string {
	m := hmac.New(sha256.New, []byte(jwtSecret))
	m.Write([]byte(input))
	return b64(m.Sum(nil))
}

func mkToken(username, role string) string {
	h := b64([]byte(`{"alg":"HS256","typ":"JWT"}`))
	p, _ := json.Marshal(map[string]any{"sub": username, "role": role})
	in := h + "." + b64(p)
	return in + "." + sign(in)
}

func parseToken(tok string) (map[string]any, bool) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 || sign(parts[0]+"."+parts[1]) != parts[2] {
		return nil, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, false
	}
	var claims map[string]any
	if json.Unmarshal(raw, &claims) != nil {
		return nil, false
	}
	return claims, true
}

func claims(r *http.Request) (map[string]any, bool) {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") {
		return nil, false
	}
	return parseToken(strings.TrimPrefix(h, "Bearer "))
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func main() {
	raw, err := os.ReadFile("data/seed.json")
	if err != nil {
		panic(err)
	}
	if err := json.Unmarshal(raw, &data); err != nil {
		panic(err)
	}
	for _, u := range data.Users {
		users[u.Username] = u
	}
	for i := range data.Accounts {
		a := data.Accounts[i]
		accts[a.ID] = &a
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, map[string]bool{"ok": true})
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<h1>Ledgerline</h1><p>Retail payments API.</p>` +
			`<script src="/app.js"></script>`))
	})
	mux.Handle("/app.js", http.FileServer(http.Dir("static")))
	mux.Handle("/v1/_internal/", http.StripPrefix("/v1/_internal/",
		http.FileServer(http.Dir("static"))))

	// POST /v1/session — login.
	mux.HandleFunc("/v1/session", func(w http.ResponseWriter, r *http.Request) {
		var in user
		_ = json.NewDecoder(r.Body).Decode(&in)
		u, ok := users[in.Username]
		if !ok || u.Password != in.Password {
			writeJSON(w, 401, map[string]string{"error": "invalid"})
			return
		}
		writeJSON(w, 200, map[string]string{"token": mkToken(u.Username, u.Role)})
	})

	// POST /v1/customers — register. VULN: mass assignment of "role".
	mux.HandleFunc("/v1/customers", func(w http.ResponseWriter, r *http.Request) {
		var in user
		_ = json.NewDecoder(r.Body).Decode(&in)
		if in.Username == "" {
			writeJSON(w, 400, map[string]string{"error": "username required"})
			return
		}
		mu.Lock()
		users[in.Username] = in // role taken straight from the body
		mu.Unlock()
		writeJSON(w, 201, map[string]string{
			"token": mkToken(in.Username, in.Role), "role": in.Role,
		})
	})

	mux.HandleFunc("/v1/me", func(w http.ResponseWriter, r *http.Request) {
		c, ok := claims(r)
		if !ok {
			writeJSON(w, 401, map[string]string{"error": "unauthenticated"})
			return
		}
		writeJSON(w, 200, c)
	})

	// POST /v1/transfer — VULN: check-then-act with a gap (TOCTOU double-spend).
	mux.HandleFunc("/v1/transfer", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := claims(r); !ok {
			writeJSON(w, 401, map[string]string{"error": "unauthenticated"})
			return
		}
		var in struct {
			From, To string
			Amount   int
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		src, dst := accts[in.From], accts[in.To]
		if src == nil || dst == nil {
			writeJSON(w, 404, map[string]string{"error": "no such account"})
			return
		}
		if src.Balance < in.Amount { // check
			writeJSON(w, 402, map[string]string{"error": "insufficient funds"})
			return
		}
		time.Sleep(150 * time.Millisecond) // the race window
		src.Balance -= in.Amount           // act
		dst.Balance += in.Amount
		writeJSON(w, 200, map[string]any{"from": src, "to": dst})
	})

	// GET /v1/ledger/contracts — admin only. The signed contracts (loot).
	mux.HandleFunc("/v1/ledger/contracts", func(w http.ResponseWriter, r *http.Request) {
		c, ok := claims(r)
		if !ok || c["role"] != "admin" {
			writeJSON(w, 403, map[string]string{"error": "admin only"})
			return
		}
		writeJSON(w, 200, data.Contracts)
	})

	// GET /v1/ops/config — admin only. Leaks the HMAC contract-signing key.
	mux.HandleFunc("/v1/ops/config", func(w http.ResponseWriter, r *http.Request) {
		c, ok := claims(r)
		if !ok || c["role"] != "admin" {
			writeJSON(w, 403, map[string]string{"error": "admin only"})
			return
		}
		writeJSON(w, 200, map[string]string{
			"contract_signing_key": data.SigningKey,
			"env":                  "production",
		})
	})

	srv := &http.Server{Addr: ":8080", Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	panic(srv.ListenAndServe())
}
