package config

import (
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

// Config holds all application configuration loaded from environment variables.
type Config struct {
	// Server
	Port string
	Env  string

	// Database
	DBDriver string
	DBDSN    string

	// Auth
	MagicLinkExpiry time.Duration
	SessionExpiry   time.Duration
	BaseURL         string

	// Notifications
	NotificationEmailProvider string
	NotificationSMSProvider   string
	SMTPHost                  string
	SMTPPort                  int
	SMTPUsername              string
	SMTPPassword              string
	SMTPFrom                  string
	SendGridAPIKey            string
	SendGridFrom              string
	SESRegion                 string
	SESUsername               string
	SESPassword               string
	SESFrom                   string
	TwilioAccountSID          string
	TwilioAuthToken           string
	TwilioFromNumber          string
	VonageAPIKey              string
	VonageAPISecret           string
	VonageFrom                string
	SNSRegion                 string
	SNSAccessKeyID            string
	SNSSecretAccessKey        string

	// Feedback
	FeedbackGitHubToken string
	FeedbackGitHubRepo  string
	FeedbackEmail       string

	// Uploads
	UploadsDir string

	// Data Retention
	DefaultRetentionDays int

	// Security
	TrustedProxies []string // CIDR ranges of trusted reverse proxies
	// TrustedProxyPrefixes holds the parsed form of TrustedProxies. Load
	// rejects a malformed entry, so this field agrees with TrustedProxies.
	TrustedProxyPrefixes []netip.Prefix
	// WebhookSecret authenticates the email provider webhooks. The routes
	// answer 404 while this value is empty, so an instance that does not set
	// it cannot be reached.
	WebhookSecret string

	// Limits
	MaxCoHostsPerEvent int

	// Email Tracking
	EmailOpenTrackingEnabled  bool
	EmailClickTrackingEnabled bool

	// Admin
	AdminEmails []string

	// Instance settings overlaid from the database (first-run setup wizard).
	// These are non-secret values that an operator may set via the UI instead
	// of editing .env. Empty/zero when the wizard has not been run.
	InstanceName    string
	DefaultTimezone string
	AllowSignups    bool
	SupportEmail    string

	// OpenID Connect sign-in. When OIDCIssuerURL is set, OIDC is the only
	// way for organizers to sign in: the magic link endpoints are disabled,
	// sessions are accepted only for organizers linked to this issuer, and
	// only linked organizers can be added as co-hosts.
	OIDCIssuerURL     string
	OIDCClientID      string
	OIDCClientSecret  string
	OIDCAllowedGroups []string // when non-empty, the groups claim must contain one of these
	OIDCProviderName  string   // label for the sign-in button
}

// Load reads environment variables (optionally from .env) and returns a Config.
func Load() (*Config, error) {
	// Load .env file if it exists; ignore error if missing.
	_ = godotenv.Load()

	port := getEnv("PORT", "8080")
	env := getEnv("ENV", "development")

	dbDriver := getEnv("DB_DRIVER", "sqlite")
	dbDSN := getEnv("DB_DSN", "/data/openrsvp.db")

	if dbDriver != "sqlite" && dbDriver != "postgres" {
		return nil, fmt.Errorf("unsupported DB_DRIVER: %s (must be sqlite or postgres)", dbDriver)
	}

	magicLinkExpiry, err := time.ParseDuration(getEnv("MAGIC_LINK_EXPIRY", "15m"))
	if err != nil {
		return nil, fmt.Errorf("invalid MAGIC_LINK_EXPIRY: %w", err)
	}

	sessionExpiry, err := time.ParseDuration(getEnv("SESSION_EXPIRY", "168h"))
	if err != nil {
		return nil, fmt.Errorf("invalid SESSION_EXPIRY: %w", err)
	}

	baseURL := getEnv("BASE_URL", "http://localhost:8080")

	smtpPort, err := strconv.Atoi(getEnv("SMTP_PORT", "587"))
	if err != nil {
		return nil, fmt.Errorf("invalid SMTP_PORT: %w", err)
	}

	if env != "development" && env != "production" {
		return nil, fmt.Errorf("invalid ENV: %s (must be development or production)", env)
	}

	portInt, err := strconv.Atoi(port)
	if err != nil || portInt < 1 || portInt > 65535 {
		return nil, fmt.Errorf("invalid PORT: %s (must be an integer between 1 and 65535)", port)
	}

	retentionDays, err := strconv.Atoi(getEnv("DEFAULT_RETENTION_DAYS", "30"))
	if err != nil {
		return nil, fmt.Errorf("invalid DEFAULT_RETENTION_DAYS: %w", err)
	}
	if retentionDays <= 0 {
		return nil, fmt.Errorf("invalid DEFAULT_RETENTION_DAYS: %d (must be greater than 0)", retentionDays)
	}

	// Parse TRUSTED_PROXIES (comma-separated CIDR ranges or IPs). A malformed
	// entry stops startup. It used to be accepted and then ignored, which let
	// a typo silently turn off the protection it was written to enable.
	var trustedProxies []string
	var trustedProxyPrefixes []netip.Prefix
	if raw := getEnv("TRUSTED_PROXIES", ""); raw != "" {
		for _, entry := range strings.Split(raw, ",") {
			entry = strings.TrimSpace(entry)
			if entry == "" {
				continue
			}
			prefix, err := parseProxyPrefix(entry)
			if err != nil {
				return nil, fmt.Errorf("invalid TRUSTED_PROXIES entry %q: %w", entry, err)
			}
			trustedProxies = append(trustedProxies, entry)
			trustedProxyPrefixes = append(trustedProxyPrefixes, prefix)
		}
	}

	// WEBHOOK_SECRET authenticates the provider webhook routes. A short value
	// is worse than none, because it looks like protection. Require 32
	// characters, which is the length of the token the README tells the
	// operator to generate.
	webhookSecret := getEnv("WEBHOOK_SECRET", "")
	if webhookSecret != "" && len(webhookSecret) < minWebhookSecretLen {
		return nil, fmt.Errorf("invalid WEBHOOK_SECRET: must be at least %d characters", minWebhookSecretLen)
	}

	maxCoHosts, err := strconv.Atoi(getEnv("MAX_COHOSTS_PER_EVENT", "10"))
	if err != nil {
		return nil, fmt.Errorf("invalid MAX_COHOSTS_PER_EVENT: %w", err)
	}
	if maxCoHosts < 1 {
		return nil, fmt.Errorf("invalid MAX_COHOSTS_PER_EVENT: %d (must be at least 1)", maxCoHosts)
	}

	cfg := &Config{
		Port: port,
		Env:  env,

		DBDriver: dbDriver,
		DBDSN:    dbDSN,

		MagicLinkExpiry: magicLinkExpiry,
		SessionExpiry:   sessionExpiry,
		BaseURL:         baseURL,

		NotificationEmailProvider: getEnv("NOTIFICATION_EMAIL_PROVIDER", "smtp"),
		NotificationSMSProvider:   getEnv("NOTIFICATION_SMS_PROVIDER", ""),
		SMTPHost:                  getEnv("SMTP_HOST", "localhost"),
		SMTPPort:                  smtpPort,
		SMTPUsername:              getEnv("SMTP_USERNAME", ""),
		SMTPPassword:              getEnv("SMTP_PASSWORD", ""),
		SMTPFrom:                  getEnv("SMTP_FROM", "noreply@openrsvp.local"),
		SendGridAPIKey:            getEnv("SENDGRID_API_KEY", ""),
		SendGridFrom:              getEnv("SENDGRID_FROM", ""),
		SESRegion:                 getEnv("SES_REGION", ""),
		SESUsername:               getEnv("SES_USERNAME", ""),
		SESPassword:               getEnv("SES_PASSWORD", ""),
		SESFrom:                   getEnv("SES_FROM", ""),
		TwilioAccountSID:          getEnv("TWILIO_ACCOUNT_SID", ""),
		TwilioAuthToken:           getEnv("TWILIO_AUTH_TOKEN", ""),
		TwilioFromNumber:          getEnv("TWILIO_FROM_NUMBER", ""),
		VonageAPIKey:              getEnv("VONAGE_API_KEY", ""),
		VonageAPISecret:           getEnv("VONAGE_API_SECRET", ""),
		VonageFrom:                getEnv("VONAGE_FROM", ""),
		SNSRegion:                 getEnv("SNS_SMS_REGION", ""),
		SNSAccessKeyID:            getEnv("SNS_SMS_ACCESS_KEY_ID", ""),
		SNSSecretAccessKey:        getEnv("SNS_SMS_SECRET_ACCESS_KEY", ""),

		FeedbackGitHubToken: getEnv("FEEDBACK_GITHUB_TOKEN", ""),
		FeedbackGitHubRepo:  getEnv("FEEDBACK_GITHUB_REPO", ""),
		FeedbackEmail:       getEnv("FEEDBACK_EMAIL", ""),

		UploadsDir: getEnv("UPLOADS_DIR", "/data/uploads"),

		DefaultRetentionDays: retentionDays,

		TrustedProxies:       trustedProxies,
		TrustedProxyPrefixes: trustedProxyPrefixes,
		WebhookSecret:        webhookSecret,

		MaxCoHostsPerEvent: maxCoHosts,

		EmailOpenTrackingEnabled:  getEnv("EMAIL_OPEN_TRACKING_ENABLED", "true") == "true",
		EmailClickTrackingEnabled: getEnv("EMAIL_CLICK_TRACKING_ENABLED", "false") == "true",

		// Instance settings: env-provided defaults. The DB (setup wizard) may
		// overlay these at startup via ApplyInstanceOverrides.
		InstanceName:    getEnv("INSTANCE_NAME", "OpenRSVP"),
		DefaultTimezone: getEnv("DEFAULT_TIMEZONE", "UTC"),
		AllowSignups:    getEnv("ALLOW_SIGNUPS", "true") == "true",
		SupportEmail:    getEnv("SUPPORT_EMAIL", ""),
	}

	// Parse ADMIN_EMAILS (comma-separated list of admin email addresses).
	if raw := getEnv("ADMIN_EMAILS", ""); raw != "" {
		for _, email := range strings.Split(raw, ",") {
			email = strings.TrimSpace(strings.ToLower(email))
			if email != "" {
				cfg.AdminEmails = append(cfg.AdminEmails, email)
			}
		}
	}

	if err := loadOIDC(cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

// loadOIDC reads and validates the OIDC_* settings into cfg.
func loadOIDC(cfg *Config) error {
	cfg.OIDCIssuerURL = strings.TrimRight(getEnv("OIDC_ISSUER_URL", ""), "/")
	cfg.OIDCClientID = getEnv("OIDC_CLIENT_ID", "")
	cfg.OIDCClientSecret = getEnv("OIDC_CLIENT_SECRET", "")
	cfg.OIDCProviderName = getEnv("OIDC_PROVIDER_NAME", "SSO")
	if raw := getEnv("OIDC_ALLOWED_GROUPS", ""); raw != "" {
		for _, g := range strings.Split(raw, ",") {
			if g = strings.TrimSpace(g); g != "" {
				cfg.OIDCAllowedGroups = append(cfg.OIDCAllowedGroups, g)
			}
		}
	}

	if cfg.OIDCIssuerURL == "" {
		if cfg.OIDCClientID != "" || cfg.OIDCClientSecret != "" || len(cfg.OIDCAllowedGroups) > 0 {
			return fmt.Errorf("OIDC_ISSUER_URL is required when other OIDC_* settings are set")
		}
		return nil
	}
	if cfg.OIDCClientID == "" {
		return fmt.Errorf("OIDC_CLIENT_ID is required when OIDC_ISSUER_URL is set")
	}
	issuer, err := url.Parse(cfg.OIDCIssuerURL)
	if err != nil || issuer.Host == "" || (issuer.Scheme != "https" && issuer.Scheme != "http") {
		return fmt.Errorf("invalid OIDC_ISSUER_URL: %q", cfg.OIDCIssuerURL)
	}
	if issuer.Scheme == "http" && !cfg.IsDevelopment() {
		return fmt.Errorf("invalid OIDC_ISSUER_URL: must use https:// when ENV=production")
	}
	return nil
}

// OIDCEnabled reports whether organizers sign in with OpenID Connect. When it
// is true, magic link sign-in is disabled.
func (c *Config) OIDCEnabled() bool {
	return c.OIDCIssuerURL != ""
}

// OIDCRedirectURL is the callback URL to register with the OIDC provider.
func (c *Config) OIDCRedirectURL() string {
	return strings.TrimRight(c.BaseURL, "/") + "/api/v1/auth/oidc/callback"
}

// IsAdminEmail returns true if the given email is in the ADMIN_EMAILS list.
func (c *Config) IsAdminEmail(email string) bool {
	email = strings.ToLower(email)
	for _, ae := range c.AdminEmails {
		if ae == email {
			return true
		}
	}
	return false
}

// ApplyInstanceOverrides overlays non-secret instance settings loaded from the
// database (the first-run setup wizard) on top of the env-derived defaults.
// Only keys present in the map are applied, so partial configuration is safe.
// Secrets (SMTP passwords, API keys, Twilio tokens) are never sourced here —
// they remain env-only. Intended to be called once at startup after the DB is
// available, e.g.:
//
//	overrides, _ := instanceConfigStore.GetAll(ctx)
//	cfg.ApplyInstanceOverrides(overrides)
func (c *Config) ApplyInstanceOverrides(overrides map[string]string) {
	if v, ok := overrides["instance_name"]; ok && v != "" {
		c.InstanceName = v
	}
	if v, ok := overrides["default_timezone"]; ok && v != "" {
		c.DefaultTimezone = v
	}
	if v, ok := overrides["allow_signups"]; ok && v != "" {
		c.AllowSignups = v == "true"
	}
	if v, ok := overrides["support_email"]; ok && v != "" {
		c.SupportEmail = v
	}
}

// IsDevelopment returns true if the environment is development.
// minWebhookSecretLen is the shortest WEBHOOK_SECRET that Load accepts.
const minWebhookSecretLen = 32

// parseProxyPrefix reads one TRUSTED_PROXIES entry. It accepts a CIDR range
// and a bare address. A bare address becomes a single-address range.
func parseProxyPrefix(entry string) (netip.Prefix, error) {
	if strings.Contains(entry, "/") {
		prefix, err := netip.ParsePrefix(entry)
		if err != nil {
			return netip.Prefix{}, err
		}
		return prefix.Masked(), nil
	}
	addr, err := netip.ParseAddr(entry)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

func (c *Config) IsDevelopment() bool {
	return c.Env == "development"
}

// SMSEnabled returns true if an SMS notification provider is configured.
func (c *Config) SMSEnabled() bool {
	return c.NotificationSMSProvider != ""
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok && value != "" {
		return value
	}
	return fallback
}
