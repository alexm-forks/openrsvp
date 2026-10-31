-- Link an organizer to an OpenID Connect identity. Organizers are matched on
-- (issuer, subject), never on email, so an email change at the identity
-- provider cannot move an account to someone else.
ALTER TABLE organizers ADD COLUMN oidc_issuer TEXT;
ALTER TABLE organizers ADD COLUMN oidc_subject TEXT;
CREATE UNIQUE INDEX idx_organizers_oidc_identity ON organizers(oidc_issuer, oidc_subject);
