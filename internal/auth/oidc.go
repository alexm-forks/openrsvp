package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/rs/zerolog"
	"golang.org/x/oauth2"

	"github.com/yannkr/openrsvp/internal/config"
)

// OIDC sign-in errors. The callback maps each one to an error code on the
// login page.
var (
	ErrOIDCUnverifiedEmail = errors.New("oidc: email missing or not verified")
	ErrOIDCNotAllowed      = errors.New("oidc: user is not in an allowed group")
	ErrOIDCSignupsClosed   = errors.New("oidc: signups are closed")
	ErrOIDCEmailConflict   = errors.New("oidc: email belongs to an organizer linked to another identity")
)

const (
	// oidcFlowCookie carries state, nonce and PKCE verifier between the login
	// redirect and the callback. It is scoped to the OIDC routes.
	oidcFlowCookie     = "oidc_flow"
	oidcFlowCookiePath = "/api/v1/auth/oidc"
	oidcFlowMaxAge     = 10 * time.Minute

	// oidcHTTPTimeout bounds every request to the identity provider.
	oidcHTTPTimeout = 10 * time.Second
)

// oidcClaims holds the ID token claims OpenRSVP reads.
type oidcClaims struct {
	Email             string   `json:"email"`
	EmailVerified     *bool    `json:"email_verified"`
	Name              string   `json:"name"`
	PreferredUsername string   `json:"preferred_username"`
	Groups            []string `json:"groups"`
}

// OIDCIdentity is a verified identity from the provider.
type OIDCIdentity struct {
	Subject string
	Email   string
	Name    string
}

// oidcClient runs the authorization code flow against the configured
// provider. Discovery runs on first use and is retried until it succeeds, so
// the server starts even while the provider is down.
type oidcClient struct {
	cfg        *config.Config
	httpClient *http.Client
	logger     zerolog.Logger

	mu       sync.Mutex
	oauth    *oauth2.Config
	verifier *oidc.IDTokenVerifier
}

func newOIDCClient(cfg *config.Config, logger zerolog.Logger) *oidcClient {
	return &oidcClient{
		cfg:        cfg,
		httpClient: &http.Client{Timeout: oidcHTTPTimeout},
		logger:     logger,
	}
}

// setup returns the OAuth2 config and ID token verifier, running discovery on
// the first successful call.
func (c *oidcClient) setup() (*oauth2.Config, *oidc.IDTokenVerifier, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.oauth != nil {
		return c.oauth, c.verifier, nil
	}

	// The provider keeps this context for later key set fetches, so it must
	// not be a request context that ends with the request. The client
	// timeout bounds each request instead.
	ctx := oidc.ClientContext(context.Background(), c.httpClient)
	provider, err := oidc.NewProvider(ctx, c.cfg.OIDCIssuerURL)
	if err != nil {
		return nil, nil, fmt.Errorf("oidc discovery: %w", err)
	}

	scopes := []string{oidc.ScopeOpenID, "email", "profile"}
	if len(c.cfg.OIDCAllowedGroups) > 0 {
		scopes = append(scopes, "groups")
	}

	endpoint := provider.Endpoint()
	if c.cfg.OIDCClientSecret == "" {
		// Public client: PKCE only, the client ID goes in the form body.
		endpoint.AuthStyle = oauth2.AuthStyleInParams
	}

	c.oauth = &oauth2.Config{
		ClientID:     c.cfg.OIDCClientID,
		ClientSecret: c.cfg.OIDCClientSecret,
		Endpoint:     endpoint,
		RedirectURL:  c.cfg.OIDCRedirectURL(),
		Scopes:       scopes,
	}
	c.verifier = provider.Verifier(&oidc.Config{ClientID: c.cfg.OIDCClientID})
	return c.oauth, c.verifier, nil
}

// randomHex returns n random bytes, hex encoded.
func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// handleOIDCLogin handles GET /api/v1/auth/oidc/login. It starts the
// authorization code flow with state, nonce and PKCE.
func (h *Handler) handleOIDCLogin(w http.ResponseWriter, r *http.Request) {
	oauthCfg, _, err := h.oidc.setup()
	if err != nil {
		h.logger.Error().Err(err).Msg("oidc: provider unavailable")
		redirectLoginError(w, r, "unavailable")
		return
	}

	state, err1 := randomHex(32)
	nonce, err2 := randomHex(32)
	if err1 != nil || err2 != nil {
		redirectLoginError(w, r, "failed")
		return
	}
	verifier := oauth2.GenerateVerifier()

	http.SetCookie(w, &http.Cookie{
		Name:     oidcFlowCookie,
		Value:    state + "." + nonce + "." + verifier,
		Path:     oidcFlowCookiePath,
		MaxAge:   int(oidcFlowMaxAge / time.Second),
		HttpOnly: true,
		Secure:   !h.cfg.IsDevelopment(),
		// Lax, not Strict: the browser must send the cookie on the
		// top-level redirect back from the provider.
		SameSite: http.SameSiteLaxMode,
	})

	authURL := oauthCfg.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier))
	http.Redirect(w, r, authURL, http.StatusFound)
}

// handleOIDCCallback handles GET /api/v1/auth/oidc/callback. It verifies the
// response, signs the organizer in and redirects to the dashboard.
func (h *Handler) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	// The flow cookie is single use whatever the outcome.
	cookie, cookieErr := r.Cookie(oidcFlowCookie)
	http.SetCookie(w, &http.Cookie{
		Name:     oidcFlowCookie,
		Value:    "",
		Path:     oidcFlowCookiePath,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   !h.cfg.IsDevelopment(),
		SameSite: http.SameSiteLaxMode,
	})

	q := r.URL.Query()
	if q.Get("error") != "" {
		h.logger.Info().Str("error", q.Get("error")).Msg("oidc: provider returned an error")
		redirectLoginError(w, r, "denied")
		return
	}

	if cookieErr != nil {
		redirectLoginError(w, r, "state")
		return
	}
	parts := strings.Split(cookie.Value, ".")
	if len(parts) != 3 || parts[0] == "" || q.Get("state") == "" ||
		subtle.ConstantTimeCompare([]byte(parts[0]), []byte(q.Get("state"))) != 1 {
		redirectLoginError(w, r, "state")
		return
	}
	nonce, verifier := parts[1], parts[2]

	code := q.Get("code")
	if code == "" {
		redirectLoginError(w, r, "failed")
		return
	}

	identity, err := h.exchangeOIDCCode(r.Context(), code, nonce, verifier)
	if err != nil {
		h.logger.Warn().Err(err).Msg("oidc: sign-in rejected")
		redirectLoginError(w, r, oidcErrorCode(err))
		return
	}

	resp, err := h.service.LoginWithOIDC(r.Context(), *identity)
	if err != nil {
		h.logger.Warn().Err(err).Str("subject", identity.Subject).Msg("oidc: sign-in rejected")
		redirectLoginError(w, r, oidcErrorCode(err))
		return
	}

	h.setSessionCookies(w, resp.Token)
	http.Redirect(w, r, "/events", http.StatusFound)
}

// exchangeOIDCCode redeems the authorization code and verifies the ID token.
func (h *Handler) exchangeOIDCCode(ctx context.Context, code, nonce, verifier string) (*OIDCIdentity, error) {
	oauthCfg, idVerifier, err := h.oidc.setup()
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(ctx, oidcHTTPTimeout)
	defer cancel()
	ctx = context.WithValue(ctx, oauth2.HTTPClient, h.oidc.httpClient)

	token, err := oauthCfg.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return nil, fmt.Errorf("exchange code: %w", err)
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return nil, errors.New("token response has no id_token")
	}
	idToken, err := idVerifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("verify id token: %w", err)
	}
	if subtle.ConstantTimeCompare([]byte(idToken.Nonce), []byte(nonce)) != 1 {
		return nil, errors.New("id token nonce mismatch")
	}
	if idToken.Subject == "" {
		return nil, errors.New("id token has no subject")
	}

	var claims oidcClaims
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("parse claims: %w", err)
	}

	if allowed := h.cfg.OIDCAllowedGroups; len(allowed) > 0 {
		if !slices.ContainsFunc(claims.Groups, func(g string) bool { return slices.Contains(allowed, g) }) {
			return nil, ErrOIDCNotAllowed
		}
	}

	// The email decides admin rights (ADMIN_EMAILS) and receives event mail,
	// so only a verified address is accepted.
	email := strings.ToLower(strings.TrimSpace(claims.Email))
	if email == "" || claims.EmailVerified == nil || !*claims.EmailVerified {
		return nil, ErrOIDCUnverifiedEmail
	}

	name := strings.TrimSpace(claims.Name)
	if name == "" {
		name = strings.TrimSpace(claims.PreferredUsername)
	}

	return &OIDCIdentity{Subject: idToken.Subject, Email: email, Name: name}, nil
}

// oidcErrorCode maps a sign-in error to the code shown on the login page.
func oidcErrorCode(err error) string {
	switch {
	case errors.Is(err, ErrOIDCUnverifiedEmail):
		return "unverified_email"
	case errors.Is(err, ErrOIDCNotAllowed), errors.Is(err, ErrOIDCSignupsClosed):
		return "not_allowed"
	case errors.Is(err, ErrOIDCEmailConflict):
		return "email_conflict"
	default:
		return "failed"
	}
}

// redirectLoginError sends the browser back to the login page with an error
// code. The code is one of a fixed set, never provider text.
func redirectLoginError(w http.ResponseWriter, r *http.Request, code string) {
	http.Redirect(w, r, "/auth/login?error="+code, http.StatusFound)
}

// LoginWithOIDC signs in the organizer linked to a verified OIDC identity and
// returns a new session. An organizer is found by issuer and subject. On the
// first sign-in, an unlinked organizer with the same verified email is linked,
// so accounts created by magic link carry over. Otherwise a new organizer is
// created, subject to the signup setting.
func (s *Service) LoginWithOIDC(ctx context.Context, id OIDCIdentity) (*AuthResponse, error) {
	issuer := s.cfg.OIDCIssuerURL

	organizer, err := s.store.FindOrganizerByOIDC(ctx, issuer, id.Subject)
	if err != nil {
		return nil, fmt.Errorf("find organizer by oidc: %w", err)
	}

	if organizer != nil {
		// Follow an email change at the provider, unless another organizer
		// holds the new address.
		if organizer.Email != id.Email {
			other, err := s.store.FindOrganizerByEmail(ctx, id.Email)
			if err != nil {
				return nil, fmt.Errorf("find organizer by email: %w", err)
			}
			if other == nil {
				if err := s.store.UpdateOrganizerEmail(ctx, organizer.ID, id.Email); err != nil {
					return nil, err
				}
				organizer.Email = id.Email
			} else {
				s.logger.Warn().Str("organizer_id", organizer.ID).Msg("oidc: new email belongs to another organizer, keeping the old one")
			}
		}
	} else {
		existing, err := s.store.FindOrganizerByEmail(ctx, id.Email)
		if err != nil {
			return nil, fmt.Errorf("find organizer by email: %w", err)
		}
		switch {
		case existing != nil && existing.OIDCSubject != "":
			return nil, ErrOIDCEmailConflict
		case existing != nil:
			if err := s.store.LinkOIDCIdentity(ctx, existing.ID, issuer, id.Subject); err != nil {
				if errors.Is(err, ErrAlreadyLinked) {
					return nil, ErrOIDCEmailConflict
				}
				return nil, err
			}
			existing.OIDCIssuer, existing.OIDCSubject = issuer, id.Subject
			organizer = existing
		default:
			if !s.allowSignups.Load() && !s.cfg.IsAdminEmail(id.Email) {
				return nil, ErrOIDCSignupsClosed
			}
			organizer, err = s.store.CreateOIDCOrganizer(ctx, id.Email, id.Name, issuer, id.Subject)
			if err != nil {
				return nil, err
			}
		}
	}

	sessionToken, err := randomHex(32)
	if err != nil {
		return nil, fmt.Errorf("generate session token: %w", err)
	}
	expiresAt := time.Now().UTC().Add(s.cfg.SessionExpiry)
	if _, err := s.store.CreateSession(ctx, hashToken(sessionToken), organizer.ID, expiresAt); err != nil {
		return nil, fmt.Errorf("create session: %w", err)
	}

	if shouldBeAdmin := s.cfg.IsAdminEmail(organizer.Email); organizer.IsAdmin != shouldBeAdmin {
		if err := s.store.SetAdminStatus(ctx, organizer.ID, shouldBeAdmin); err != nil {
			s.logger.Error().Err(err).Str("organizer_id", organizer.ID).Msg("failed to sync admin status")
		} else {
			organizer.IsAdmin = shouldBeAdmin
		}
	}

	return &AuthResponse{Token: sessionToken, Organizer: organizer}, nil
}

// IsOIDCLinked reports whether the organizer is linked to the configured OIDC
// issuer. When OIDC is enabled, only linked organizers may hold a session or
// be added as co-hosts.
func (s *Service) IsOIDCLinked(o *Organizer) bool {
	return o != nil && o.OIDCSubject != "" && o.OIDCIssuer == s.cfg.OIDCIssuerURL
}
