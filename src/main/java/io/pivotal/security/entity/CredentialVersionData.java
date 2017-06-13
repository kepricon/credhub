package io.pivotal.security.entity;

import io.pivotal.security.util.InstantMillisecondsConverter;
import org.hibernate.annotations.GenericGenerator;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.Instant;
import java.util.UUID;
import javax.persistence.Column;
import javax.persistence.Convert;
import javax.persistence.DiscriminatorColumn;
import javax.persistence.DiscriminatorType;
import javax.persistence.Entity;
import javax.persistence.EntityListeners;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.Inheritance;
import javax.persistence.InheritanceType;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.Table;

import static io.pivotal.security.constants.EncryptionConstants.ENCRYPTED_BYTES;
import static io.pivotal.security.constants.EncryptionConstants.NONCE_SIZE;
import static io.pivotal.security.constants.UuidConstants.UUID_BYTES;

@Entity
@Table(name = "CredentialVersion")
@Inheritance(strategy = InheritanceType.JOINED)
@EntityListeners(AuditingEntityListener.class)
@DiscriminatorColumn(name = "credential.type", discriminatorType = DiscriminatorType.STRING)
public abstract class CredentialVersionData<Z extends CredentialVersionData> {

  // Use VARBINARY to make all 3 DB types happy.
  // H2 doesn't distinguish between "binary" and "varbinary" - see
  // https://hibernate.atlassian.net/browse/HHH-9835 and
  // https://github.com/h2database/h2database/issues/345
  @Id
  @Column(length = UUID_BYTES, columnDefinition = "VARBINARY")
  @GeneratedValue(generator = "uuid2")
  @GenericGenerator(name = "uuid2", strategy = "uuid2")
  private UUID uuid;

  @Column(length = ENCRYPTED_BYTES + NONCE_SIZE, name = "encrypted_value")
  private byte[] encryptedValue;

  @Column(length = NONCE_SIZE)
  private byte[] nonce;

  @Convert(converter = InstantMillisecondsConverter.class)
  @Column(nullable = false, columnDefinition = "BIGINT NOT NULL")
  @CreatedDate
  private Instant versionCreatedAt;

  @Convert(converter = InstantMillisecondsConverter.class)
  @Column(nullable = false, columnDefinition = "BIGINT NOT NULL")
  @CreatedDate
  @LastModifiedDate
  @SuppressWarnings("unused")
  //secrets are updated in place when encryption keys are rotated
  private Instant updatedAt;

  @Column(length = UUID_BYTES, columnDefinition = "VARBINARY")
  private UUID encryptionKeyUuid;

  @ManyToOne
  @JoinColumn(name = "credential_uuid", nullable = false)
  private Credential credential;

  public CredentialVersionData(Credential credential) {
    if (this.credential != null) {
      this.credential.setName(credential.getName());
    } else {
      setCredential(credential);
    }
  }

  public CredentialVersionData(String name) {
    this(new Credential(name));
  }

  public CredentialVersionData() {
    this((String) null);
  }

  public UUID getUuid() {
    return uuid;
  }

  public Z setUuid(UUID uuid) {
    this.uuid = uuid;
    return (Z) this;
  }

  public Credential getCredential() {
    return credential;
  }

  public void setCredential(Credential credential) {
    this.credential = credential;
  }

  public byte[] getEncryptedValue() {
    return encryptedValue;
  }

  public Z setEncryptedValue(byte[] encryptedValue) {
    this.encryptedValue = encryptedValue;
    return (Z) this;
  }

  public byte[] getNonce() {
    return nonce;
  }

  public Z setNonce(byte[] nonce) {
    this.nonce = nonce;
    return (Z) this;
  }

  public abstract String getCredentialType();

  public UUID getEncryptionKeyUuid() {
    return encryptionKeyUuid;
  }

  public Z setEncryptionKeyUuid(UUID encryptionKeyUuid) {
    this.encryptionKeyUuid = encryptionKeyUuid;
    return (Z) this;
  }

  public Instant getVersionCreatedAt() {
    return versionCreatedAt;
  }

  public Z setVersionCreatedAt(Instant versionCreatedAt) {
    this.versionCreatedAt = versionCreatedAt;
    return (Z) this;
  }
}
