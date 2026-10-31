package auth_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yannkr/openrsvp/internal/auth"
	"github.com/yannkr/openrsvp/internal/config"
	"github.com/yannkr/openrsvp/internal/database"
	"github.com/yannkr/openrsvp/internal/testutil"
)

// fakeIdP is a minimal OpenID provider: discovery, JWKS and a token endpoint
// that checks the PKCE verifier and returns an ID token with the configured
// claims.
type fakeIdP struct {
	t      *testing.T
	server *httptest.Server
	key    *rsa.PrivateKey

	mu            sync.Mutex
	claims        map[string]any
	nonce         string // nonce from the last authorization request
	challenge     string // PKCE challenge from the last authorization request
	nonceOverride string // when set, the ID token carries this nonce instead
}

func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	idp := &fakeIdP{t: t, key: key}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		base := idp.server.URL
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                base,
			"authorization_endpoint":                base + "/authorize",
			"token_endpoint":                        base + "/token",
			"jwks_uri":                              base + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
			{Key: &key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"},
		}})
	})
	mux.HandleFunc("/token", idp.handleToken)
	idp.server = httptest.NewServer(mux)
	t.Cleanup(idp.server.Close)
	return idp
}

func (idp *fakeIdP) handleToken(w http.ResponseWriter, r *http.Request) {
	require.NoError(idp.t, r.ParseForm())
	idp.mu.Lock()
	defer idp.mu.Unlock()

	sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	if r.PostForm.Get("code") != "good-code" ||
		base64.RawURLEncoding.EncodeToString(sum[:]) != idp.challenge {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
		return
	}

	nonce := idp.nonce
	if idp.nonceOverride != "" {
		nonce = idp.nonceOverride
	}
	claims := map[string]any{
		"iss":   idp.server.URL,
		"aud":   "openrsvp",
		"iat":   time.Now().Unix(),
		"exp":   time.Now().Add(5 * time.Minute).Unix(),
		"nonce": nonce,
	}
	for k, v := range idp.claims {
		claims[k] = v
	}
	payload, err := json.Marshal(claims)
	require.NoError(idp.t, err)

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: idp.key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "k1"))
	require.NoError(idp.t, err)
	sig, err := signer.Sign(payload)
	require.NoError(idp.t, err)
	idToken, err := sig.CompactSerialize()
	require.NoError(idp.t, err)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token": "at",
		"token_type":   "Bearer",
		"expires_in":   300,
		"id_token":     idToken,
	})
}

func (idp *fakeIdP) setClaims(claims map[string]any) {
	idp.mu.Lock()
	defer idp.mu.Unlock()
	idp.claims = claims
}

type oidcEnv struct {
	idp     *fakeIdP
	cfg     *config.Config
	db      database.DB
	store   *auth.Store
	service *auth.Service
	routes  http.Handler
}

func setupOIDC(t *testing.T, mutate ...func(*config.Config)) *oidcEnv {
	t.Helper()
	idp := newFakeIdP(t)
	db := testutil.NewTestDB(t)
	cfg := testutil.TestConfig()
	cfg.OIDCIssuerURL = idp.server.URL
	cfg.OIDCClientID = "openrsvp"
	cfg.OIDCProviderName = "Pocket ID"
	for _, m := range mutate {
		m(cfg)
	}
	store := auth.NewStore(db)
	svc := auth.NewService(store, cfg, zerolog.Nop())
	handler := auth.NewHandler(svc, cfg, zerolog.Nop())
	return &oidcEnv{idp: idp, cfg: cfg, db: db, store: store, service: svc, routes: handler.Routes()}
}

func verifiedClaims(sub, email string) map[string]any {
	return map[string]any{"sub": sub, "email": email, "email_verified": true, "name": "Alex"}
}

// startLogin calls /oidc/login and records the nonce and PKCE challenge the
// browser would carry to the provider. It returns the flow cookie and state.
func (e *oidcEnv) startLogin(t *testing.T) (*http.Cookie, string) {
	t.Helper()
	rr := httptest.NewRecorder()
	e.routes.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/oidc/login", nil))
	require.Equal(t, http.StatusFound, rr.Code)

	loc, err := url.Parse(rr.Header().Get("Location"))
	require.NoError(t, err)
	assert.Equal(t, e.idp.server.URL+"/authorize", loc.Scheme+"://"+loc.Host+loc.Path)
	q := loc.Query()
	assert.Equal(t, "S256", q.Get("code_challenge_method"))
	assert.Equal(t, e.cfg.OIDCRedirectURL(), q.Get("redirect_uri"))

	e.idp.mu.Lock()
	e.idp.nonce = q.Get("nonce")
	e.idp.challenge = q.Get("code_challenge")
	e.idp.mu.Unlock()

	var flow *http.Cookie
	for _, c := range rr.Result().Cookies() {
		if c.Name == "oidc_flow" {
			flow = c
		}
	}
	require.NotNil(t, flow, "login must set the flow cookie")
	assert.True(t, flow.HttpOnly)
	assert.Equal(t, http.SameSiteLaxMode, flow.SameSite)
	return flow, q.Get("state")
}

// callback calls /oidc/callback the way the provider redirect would.
func (e *oidcEnv) callback(t *testing.T, flow *http.Cookie, state, code string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/oidc/callback?code="+url.QueryEscape(code)+"&state="+url.QueryEscape(state), nil)
	if flow != nil {
		req.AddCookie(flow)
	}
	rr := httptest.NewRecorder()
	e.routes.ServeHTTP(rr, req)
	return rr
}

// signIn runs a full login with the given ID token claims.
func (e *oidcEnv) signIn(t *testing.T, claims map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	e.idp.setClaims(claims)
	flow, state := e.startLogin(t)
	return e.callback(t, flow, state, "good-code")
}

func sessionCookie(rr *httptest.ResponseRecorder) string {
	for _, c := range rr.Result().Cookies() {
		if c.Name == "session" && c.MaxAge > 0 {
			return c.Value
		}
	}
	return ""
}

func TestOIDC_NewOrganizerSignsIn(t *testing.T) {
	env := setupOIDC(t)

	rr := env.signIn(t, verifiedClaims("user-1", "Alex@Example.com"))
	require.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, "/events", rr.Header().Get("Location"))

	token := sessionCookie(rr)
	require.NotEmpty(t, token)

	me := testutil.DoAuthRequest(t, env.routes, http.MethodGet, "/me", token, nil)
	require.Equal(t, http.StatusOK, me.Code)
	body := testutil.ParseJSON(t, me)
	assert.Equal(t, "alex@example.com", body["email"])
	assert.Equal(t, "Alex", body["name"])
	assert.NotContains(t, body, "OIDCSubject")

	org, err := env.store.FindOrganizerByOIDC(context.Background(), env.cfg.OIDCIssuerURL, "user-1")
	require.NoError(t, err)
	require.NotNil(t, org)

	// A second sign-in reuses the same organizer.
	rr = env.signIn(t, verifiedClaims("user-1", "alex@example.com"))
	require.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, 1, countRows(t, env.db, "SELECT COUNT(*) FROM organizers WHERE email = ?", "alex@example.com"))
}

func TestOIDC_RejectsUnverifiedOrMissingEmail(t *testing.T) {
	cases := map[string]map[string]any{
		"unverified":   {"sub": "u", "email": "a@example.com", "email_verified": false},
		"no claim":     {"sub": "u", "email": "a@example.com"},
		"missing mail": {"sub": "u", "email_verified": true},
	}
	for name, claims := range cases {
		t.Run(name, func(t *testing.T) {
			env := setupOIDC(t)
			rr := env.signIn(t, claims)
			require.Equal(t, http.StatusFound, rr.Code)
			assert.Equal(t, "/auth/login?error=unverified_email", rr.Header().Get("Location"))
			assert.Empty(t, sessionCookie(rr))
		})
	}
}

func TestOIDC_AllowedGroups(t *testing.T) {
	env := setupOIDC(t, func(c *config.Config) { c.OIDCAllowedGroups = []string{"openrsvp"} })

	claims := verifiedClaims("u", "a@example.com")
	claims["groups"] = []string{"other"}
	rr := env.signIn(t, claims)
	assert.Equal(t, "/auth/login?error=not_allowed", rr.Header().Get("Location"))
	assert.Empty(t, sessionCookie(rr))

	claims["groups"] = []string{"other", "openrsvp"}
	rr = env.signIn(t, claims)
	assert.Equal(t, "/events", rr.Header().Get("Location"))
	assert.NotEmpty(t, sessionCookie(rr))
}

func TestOIDC_GroupsScopeRequestedOnlyWhenNeeded(t *testing.T) {
	env := setupOIDC(t, func(c *config.Config) { c.OIDCAllowedGroups = []string{"g"} })
	rr := httptest.NewRecorder()
	env.routes.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/oidc/login", nil))
	loc, _ := url.Parse(rr.Header().Get("Location"))
	assert.Equal(t, "openid email profile groups", loc.Query().Get("scope"))

	env = setupOIDC(t)
	rr = httptest.NewRecorder()
	env.routes.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/oidc/login", nil))
	loc, _ = url.Parse(rr.Header().Get("Location"))
	assert.Equal(t, "openid email profile", loc.Query().Get("scope"))
}

func TestOIDC_StateChecks(t *testing.T) {
	env := setupOIDC(t)
	env.idp.setClaims(verifiedClaims("u", "a@example.com"))

	flow, _ := env.startLogin(t)
	rr := env.callback(t, flow, "wrong-state", "good-code")
	assert.Equal(t, "/auth/login?error=state", rr.Header().Get("Location"))

	_, state := env.startLogin(t)
	rr = env.callback(t, nil, state, "good-code")
	assert.Equal(t, "/auth/login?error=state", rr.Header().Get("Location"), "callback without flow cookie")

	// The callback always clears the flow cookie.
	var cleared bool
	for _, c := range rr.Result().Cookies() {
		if c.Name == "oidc_flow" && c.MaxAge < 0 {
			cleared = true
		}
	}
	assert.True(t, cleared)
}

func TestOIDC_RejectsNonceMismatchAndBadCode(t *testing.T) {
	env := setupOIDC(t)
	env.idp.setClaims(verifiedClaims("u", "a@example.com"))

	env.idp.nonceOverride = "replayed-nonce"
	flow, state := env.startLogin(t)
	rr := env.callback(t, flow, state, "good-code")
	assert.Equal(t, "/auth/login?error=failed", rr.Header().Get("Location"))
	env.idp.nonceOverride = ""

	flow, state = env.startLogin(t)
	rr = env.callback(t, flow, state, "bad-code")
	assert.Equal(t, "/auth/login?error=failed", rr.Header().Get("Location"))
	assert.Empty(t, sessionCookie(rr))
}

func TestOIDC_ProviderErrorIsReported(t *testing.T) {
	env := setupOIDC(t)
	flow, state := env.startLogin(t)
	req := httptest.NewRequest(http.MethodGet, "/oidc/callback?error=access_denied&state="+state, nil)
	req.AddCookie(flow)
	rr := httptest.NewRecorder()
	env.routes.ServeHTTP(rr, req)
	assert.Equal(t, "/auth/login?error=denied", rr.Header().Get("Location"))
}

func TestOIDC_LinksExistingOrganizerByVerifiedEmail(t *testing.T) {
	env := setupOIDC(t)
	ctx := context.Background()

	legacy, err := env.store.CreateOrganizer(ctx, "old@example.com")
	require.NoError(t, err)

	// A session left over from magic link sign-in no longer counts.
	createSession(t, env.store, legacy.ID, "legacy-session-token")
	rr := testutil.DoAuthRequest(t, env.routes, http.MethodGet, "/me", "legacy-session-token", nil)
	assert.Equal(t, http.StatusUnauthorized, rr.Code)

	rr = env.signIn(t, verifiedClaims("user-9", "old@example.com"))
	require.Equal(t, "/events", rr.Header().Get("Location"))

	linked, err := env.store.FindOrganizerByOIDC(ctx, env.cfg.OIDCIssuerURL, "user-9")
	require.NoError(t, err)
	require.NotNil(t, linked)
	assert.Equal(t, legacy.ID, linked.ID, "the existing account is linked, not duplicated")
}

func TestOIDC_EmailHeldByAnotherIdentity(t *testing.T) {
	env := setupOIDC(t)

	rr := env.signIn(t, verifiedClaims("owner", "taken@example.com"))
	require.Equal(t, "/events", rr.Header().Get("Location"))

	rr = env.signIn(t, verifiedClaims("intruder", "taken@example.com"))
	assert.Equal(t, "/auth/login?error=email_conflict", rr.Header().Get("Location"))
	assert.Empty(t, sessionCookie(rr))
}

func TestOIDC_EmailChangeAtProviderFollows(t *testing.T) {
	env := setupOIDC(t)
	ctx := context.Background()

	env.signIn(t, verifiedClaims("u", "first@example.com"))
	env.signIn(t, verifiedClaims("u", "second@example.com"))

	org, err := env.store.FindOrganizerByOIDC(ctx, env.cfg.OIDCIssuerURL, "u")
	require.NoError(t, err)
	assert.Equal(t, "second@example.com", org.Email)

	// An address another organizer already holds is not taken over.
	env.signIn(t, verifiedClaims("other", "third@example.com"))
	env.signIn(t, verifiedClaims("u", "third@example.com"))
	org, err = env.store.FindOrganizerByOIDC(ctx, env.cfg.OIDCIssuerURL, "u")
	require.NoError(t, err)
	assert.Equal(t, "second@example.com", org.Email)
}

func TestOIDC_SignupsClosed(t *testing.T) {
	env := setupOIDC(t, func(c *config.Config) {
		c.AdminEmails = []string{"admin@example.com"}
	})
	env.service.SetAllowSignups(false)

	rr := env.signIn(t, verifiedClaims("stranger", "stranger@example.com"))
	assert.Equal(t, "/auth/login?error=not_allowed", rr.Header().Get("Location"))

	rr = env.signIn(t, verifiedClaims("admin", "admin@example.com"))
	require.Equal(t, "/events", rr.Header().Get("Location"))
	me := testutil.DoAuthRequest(t, env.routes, http.MethodGet, "/me", sessionCookie(rr), nil)
	assert.Equal(t, true, testutil.ParseJSON(t, me)["isAdmin"])
}

func TestOIDC_MagicLinkDisabled(t *testing.T) {
	env := setupOIDC(t)

	rr := testutil.DoRequest(t, env.routes, http.MethodPost, "/magic-link", map[string]string{"email": "a@example.com"})
	assert.Equal(t, http.StatusNotFound, rr.Code)
	rr = testutil.DoRequest(t, env.routes, http.MethodPost, "/verify", map[string]string{"token": "x"})
	assert.Equal(t, http.StatusNotFound, rr.Code)

	// The service refuses too, whatever route reaches it.
	assert.ErrorIs(t, env.service.RequestMagicLink(context.Background(), "a@example.com"), auth.ErrMagicLinkDisabled)
	assert.Equal(t, 0, countRows(t, env.db, "SELECT COUNT(*) FROM organizers WHERE email = ?", "a@example.com"))
}

func TestOIDC_RoutesAbsentWithoutOIDC(t *testing.T) {
	env := setupAuthHandler(t)
	rr := testutil.DoRequest(t, env.handler.Routes(), http.MethodGet, "/oidc/login", nil)
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestOIDC_ProviderDownAtLogin(t *testing.T) {
	env := setupOIDC(t)
	env.idp.server.Close()

	rr := httptest.NewRecorder()
	env.routes.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/oidc/login", nil))
	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, "/auth/login?error=unavailable", rr.Header().Get("Location"))
}
