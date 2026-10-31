package auth

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog"

	"github.com/yannkr/openrsvp/internal/config"
	"github.com/yannkr/openrsvp/internal/errcode"
)

// Handler provides HTTP handlers for authentication endpoints.
type Handler struct {
	service *Service
	cfg     *config.Config
	logger  zerolog.Logger
	oidc    *oidcClient // nil unless OIDC sign-in is configured
}

// NewHandler creates a new auth Handler.
func NewHandler(service *Service, cfg *config.Config, logger zerolog.Logger) *Handler {
	h := &Handler{
		service: service,
		cfg:     cfg,
		logger:  logger,
	}
	if cfg.OIDCEnabled() {
		h.oidc = newOIDCClient(cfg, logger)
	}
	return h
}

// Routes returns a chi.Router with all auth routes mounted.
// An optional loginRateLimit middleware is applied only to the login
// endpoints (magic-link, verify) to prevent brute-force attacks without
// penalising session management calls (/me, /logout) that the SPA
// issues on every page load.
func (h *Handler) Routes(loginRateLimit ...func(http.Handler) http.Handler) chi.Router {
	r := chi.NewRouter()

	r.Group(func(rl chi.Router) {
		if len(loginRateLimit) > 0 && loginRateLimit[0] != nil {
			rl.Use(loginRateLimit[0])
		}
		if h.oidc != nil {
			// OIDC is the only sign-in method. The magic link endpoints
			// stay registered so they answer with a clear 404.
			rl.Get("/oidc/login", h.handleOIDCLogin)
			rl.Get("/oidc/callback", h.handleOIDCCallback)
			rl.Post("/magic-link", h.handleMagicLinkDisabled)
			rl.Post("/verify", h.handleMagicLinkDisabled)
		} else {
			rl.Post("/magic-link", h.handleMagicLink)
			rl.Post("/verify", h.handleVerify)
		}
	})

	r.Post("/logout", h.handleLogout)
	r.With(RequireAuth(h.service)).Get("/me", h.handleMe)
	r.With(RequireAuth(h.service)).Patch("/me", h.handleUpdateMe)
	r.With(RequireAuth(h.service)).Get("/me/export", h.handleExportMe)
	r.With(RequireAuth(h.service)).Delete("/me", h.handleDeleteMe)

	return r
}

// handleMagicLink handles POST /api/v1/auth/magic-link.
func (h *Handler) handleMagicLink(w http.ResponseWriter, r *http.Request) {
	var req MagicLinkRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	req.Email = strings.TrimSpace(strings.ToLower(req.Email))

	if req.Email == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "email is required"})
		return
	}

	// Always return a generic message to avoid leaking whether an email exists.
	if err := h.service.RequestMagicLink(r.Context(), req.Email); err != nil {
		if err == ErrInvalidEmail {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid email address"})
			return
		}
		h.logger.Error().Err(err).Str("email", req.Email).Msg("failed to request magic link")
	}

	writeJSON(w, http.StatusOK, MagicLinkResponse{
		Message: "If an account exists for this email, a magic link has been sent. Please check your inbox.",
	})
}

// handleVerify handles POST /api/v1/auth/verify.
func (h *Handler) handleVerify(w http.ResponseWriter, r *http.Request) {
	var req VerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	req.Token = strings.TrimSpace(req.Token)

	if req.Token == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "token is required"})
		return
	}

	resp, err := h.service.VerifyMagicLink(r.Context(), req.Token)
	if err != nil {
		if err == ErrInvalidToken {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid or expired token"})
			return
		}
		ref := errcode.Ref()
		h.logger.Error().Err(err).Str("error_code", ref).Msg("failed to verify magic link")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "an internal error occurred (ref: " + ref + ")"})
		return
	}

	h.setSessionCookies(w, resp.Token)

	writeJSON(w, http.StatusOK, resp)
}

// handleMagicLinkDisabled answers the magic link endpoints when OIDC is the
// sign-in method.
func (h *Handler) handleMagicLinkDisabled(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusNotFound, map[string]string{"error": "magic link sign-in is disabled"})
}

// setSessionCookies sets the session cookie after a successful sign-in and
// clears the pre-login CSRF token.
func (h *Handler) setSessionCookies(w http.ResponseWriter, token string) {
	// Set the session cookie. MaxAge mirrors the server-side session
	// lifetime so the browser-side cookie does not outlive the database
	// record (otherwise the cookie sits around looking valid while every
	// authenticated request 401s).
	secure := !h.cfg.IsDevelopment()
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    token,
		Path:     "/",
		MaxAge:   int(h.cfg.SessionExpiry / time.Second),
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})

	// Clear the pre-login CSRF token so the CSRF middleware issues a fresh
	// session-bound token on the next GET request.
	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: false,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
	})
}

// handleLogout handles POST /api/v1/auth/logout.
func (h *Handler) handleLogout(w http.ResponseWriter, r *http.Request) {
	token := extractToken(r)
	if token == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	if err := h.service.Logout(r.Context(), token); err != nil {
		if err == ErrSessionNotFound {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		ref := errcode.Ref()
		h.logger.Error().Err(err).Str("error_code", ref).Msg("failed to logout")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "an internal error occurred (ref: " + ref + ")"})
		return
	}

	// Clear the session cookie.
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   !h.cfg.IsDevelopment(),
		SameSite: http.SameSiteLaxMode,
	})

	writeJSON(w, http.StatusOK, map[string]string{"message": "logged out"})
}

// handleMe handles GET /api/v1/auth/me.
func (h *Handler) handleMe(w http.ResponseWriter, r *http.Request) {
	organizer := OrganizerFromContext(r.Context())
	if organizer == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	writeJSON(w, http.StatusOK, organizer)
}

// handleUpdateMe handles PATCH /api/v1/auth/me.
func (h *Handler) handleUpdateMe(w http.ResponseWriter, r *http.Request) {
	organizer := OrganizerFromContext(r.Context())
	if organizer == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	var req UpdateProfileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	if req.Name != nil {
		organizer.Name = *req.Name
	}
	if req.Timezone != nil {
		organizer.Timezone = *req.Timezone
	}

	if err := h.service.UpdateProfile(r.Context(), organizer); err != nil {
		ref := errcode.Ref()
		h.logger.Error().Err(err).Str("error_code", ref).Msg("failed to update profile")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "an internal error occurred (ref: " + ref + ")"})
		return
	}

	writeJSON(w, http.StatusOK, organizer)
}

// handleExportMe handles GET /api/v1/auth/me/export. It returns a JSON
// document containing the authenticated organizer's profile and all of the
// data they own (events and their children). The response is scoped strictly
// to the requesting organizer.
func (h *Handler) handleExportMe(w http.ResponseWriter, r *http.Request) {
	organizer := OrganizerFromContext(r.Context())
	if organizer == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	doc, err := h.service.ExportData(r.Context(), organizer.ID)
	if err != nil {
		ref := errcode.Ref()
		h.logger.Error().Err(err).Str("error_code", ref).Msg("failed to export organizer data")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "an internal error occurred (ref: " + ref + ")"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="openrsvp-export.json"`)
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(doc)
}

// handleDeleteMe handles DELETE /api/v1/auth/me. It permanently deletes the
// authenticated organizer's account and every record they own, then clears
// the session cookie.
func (h *Handler) handleDeleteMe(w http.ResponseWriter, r *http.Request) {
	organizer := OrganizerFromContext(r.Context())
	if organizer == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	if err := h.service.DeleteAccount(r.Context(), organizer.ID); err != nil {
		ref := errcode.Ref()
		h.logger.Error().Err(err).Str("error_code", ref).Msg("failed to delete account")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "an internal error occurred (ref: " + ref + ")"})
		return
	}

	// Clear the session cookie, mirroring handleLogout.
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   !h.cfg.IsDevelopment(),
		SameSite: http.SameSiteLaxMode,
	})

	w.WriteHeader(http.StatusNoContent)
}

// extractToken reads the session token from the cookie or Authorization header.
func extractToken(r *http.Request) string {
	// Try cookie first.
	if cookie, err := r.Cookie("session"); err == nil && cookie.Value != "" {
		return cookie.Value
	}

	// Fall back to Authorization header.
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		return strings.TrimPrefix(authHeader, "Bearer ")
	}

	return ""
}

// writeJSON encodes data as JSON and writes it to the response.
func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}
