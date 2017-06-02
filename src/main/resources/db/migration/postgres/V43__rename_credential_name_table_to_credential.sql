ALTER TABLE credential_name RENAME TO credential;

ALTER TABLE access_entry
  RENAME COLUMN credential_name_uuid
  TO credential_uuid;

ALTER TABLE access_entry
  ADD CONSTRAINT credential_uuid_access_fkey
  FOREIGN KEY (credential_uuid)
  REFERENCES credential(uuid)
  ON DELETE CASCADE;

ALTER TABLE access_entry
  DROP CONSTRAINT credential_name_uuid_access_fkey;

ALTER TABLE credential_version
  RENAME COLUMN credential_name_uuid
  TO credential_uuid;

ALTER TABLE credential_version
  ADD CONSTRAINT credential_uuid_fkey
  FOREIGN KEY(credential_uuid)
  REFERENCES credential(uuid)
  ON DELETE CASCADE;

ALTER TABLE credential_version
  DROP CONSTRAINT credential_name_uuid_fkey;
