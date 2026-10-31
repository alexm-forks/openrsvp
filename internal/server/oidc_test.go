package server

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/yannkr/openrsvp/internal/auth"
	"github.com/yannkr/openrsvp/internal/config"
)

const testOIDCIssuer = "https://id.example.com"

func newOIDCTestServer(t *testing.T) (http.Handler, *auth.Store, func(email, subject string) string) {
	t.Helper()
	srv, db := newTestServerWith(t, func(cfg *config.Config) {
		// Discovery runs on the first login, so no provider is needed here.
		cfg.OIDCIssuerURL = testOIDCIssuer
		cfg.OIDCClientID = "openrsvp"
		cfg.OIDCProviderName = "Pocket ID"
	})
	store := auth.NewStore(db)

	// linkedSession creates an organizer, links it to an OIDC subject when
	// subject is non-empty, and returns a session token for it.
	linkedSession := func(email, subject string) string {
		t.Helper()
		session := createSession(t, db, email)
		if subject != "" {
			org, err := store.FindOrganizerByEmail(context.Background(), email)
			if err != nil || org == nil {
				t.Fatalf("find organizer: %v", err)
			}
			if err := store.LinkOIDCIdentity(context.Background(), org.ID, testOIDCIssuer, subject); err != nil {
				t.Fatalf("link: %v", err)
			}
		}
		return session
	}

	return srv.http.Handler, store, linkedSession
}

func TestOIDCMode_CoHostsMustBeOIDCLinked(t *testing.T) {
	h, store, linkedSession := newOIDCTestServer(t)
	ctx := context.Background()

	ownerSession := linkedSession("owner@example.com", "owner-sub")
	linkedSession("friend@example.com", "friend-sub")
	if _, err := store.CreateOrganizer(ctx, "legacy@example.com"); err != nil {
		t.Fatal(err)
	}

	rr := authedJSON(t, h, ownerSession, http.MethodPost, "/api/v1/events", map[string]any{
		"title":     "Party",
		"eventDate": time.Now().Add(48 * time.Hour).UTC().Format(time.RFC3339),
		"timezone":  "UTC",
	})
	if rr.Code != http.StatusCreated {
		t.Fatalf("create event: got %d (body=%s)", rr.Code, rr.Body.String())
	}
	var created struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &created)

	path := "/api/v1/events/" + created.Data.ID + "/cohosts"

	rr = authedJSON(t, h, ownerSession, http.MethodPost, path, map[string]string{"email": "legacy@example.com"})
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("add unlinked co-host: got %d, want 400 (body=%s)", rr.Code, rr.Body.String())
	}

	rr = authedJSON(t, h, ownerSession, http.MethodPost, path, map[string]string{"email": "friend@example.com"})
	if rr.Code != http.StatusCreated && rr.Code != http.StatusOK {
		t.Fatalf("add linked co-host: got %d (body=%s)", rr.Code, rr.Body.String())
	}
}

func TestOIDCMode_UnlinkedSessionRejectedAndConfigReportsMode(t *testing.T) {
	h, _, linkedSession := newOIDCTestServer(t)

	legacy := linkedSession("legacy@example.com", "")
	rr := authedJSON(t, h, legacy, http.MethodGet, "/api/v1/events", nil)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("unlinked session: got %d, want 401", rr.Code)
	}

	rr = doJSON(h, http.MethodGet, "/api/v1/config", nil)
	var cfg struct {
		Data struct {
			AuthMode string `json:"authMode"`
			OIDCName string `json:"oidcName"`
		} `json:"data"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &cfg)
	if cfg.Data.AuthMode != "oidc" || cfg.Data.OIDCName != "Pocket ID" {
		t.Fatalf("config: got %+v", cfg.Data)
	}

	body, _ := json.Marshal(map[string]string{"email": "new@example.com"})
	rr = doJSON(h, http.MethodPost, "/api/v1/auth/magic-link", body)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("magic link in OIDC mode: got %d, want 404", rr.Code)
	}
}
