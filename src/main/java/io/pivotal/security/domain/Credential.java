package io.pivotal.security.domain;

import io.pivotal.security.data.CredentialVersionDataService;
import io.pivotal.security.entity.CredentialVersionData;

import java.time.Instant;
import java.util.UUID;

public abstract class Credential<Z extends Credential> {

  protected CredentialVersionData delegate;
  protected Encryptor encryptor;

  public Credential(CredentialVersionData delegate) {
    this.delegate = delegate;
  }

  public abstract String getCredentialType();

  public abstract void rotate();

  public UUID getUuid() {
    return delegate.getUuid();
  }

  public Z setUuid(UUID uuid) {
    delegate.setUuid(uuid);
    return (Z) this;
  }

  public String getName() {
    return delegate.getCredential().getName();
  }

  public Instant getVersionCreatedAt() {
    return delegate.getVersionCreatedAt();
  }

  public Z setVersionCreatedAt(Instant versionCreatedAt) {
    delegate.setVersionCreatedAt(versionCreatedAt);
    return (Z) this;
  }

  public Z setEncryptor(Encryptor encryptor) {
    this.encryptor = encryptor;
    return (Z) this;
  }

  public <Z extends Credential> Z save(CredentialVersionDataService credentialVersionDataService) {
    return (Z) credentialVersionDataService.save(delegate);
  }

  public io.pivotal.security.entity.Credential getCredentialName() {
    return delegate.getCredential();
  }

  protected void copyNameReferenceFrom(Credential credential) {
    this.delegate.setCredential(credential.delegate.getCredential());
  }

  public void createName(String name) {
    delegate.setCredential(new io.pivotal.security.entity.Credential(name));
  }
}
