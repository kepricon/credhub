ALTER TABLE credential_version
  DROP COLUMN type;

ALTER TABLE credential
  ADD COLUMN type VARCHAR(31) NOT NULL;
