DROP INDEX idx_organizers_oidc_identity;
ALTER TABLE organizers DROP COLUMN oidc_subject;
ALTER TABLE organizers DROP COLUMN oidc_issuer;
