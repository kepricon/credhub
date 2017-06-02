package io.pivotal.security.repository;

import io.pivotal.security.entity.CredentialVersionData;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Slice;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.UUID;

public interface CredentialVersionRepository extends JpaRepository<CredentialVersionData, UUID> {

  int BATCH_SIZE = 50;

  CredentialVersionData findOneByUuid(UUID uuid);

  Long countByEncryptionKeyUuidNot(UUID encryptionKeyUuid);

  Long countByEncryptionKeyUuidIn(List<UUID> encryptionKeyUuids);

  Slice<CredentialVersionData> findByEncryptionKeyUuidIn(List<UUID> encryptionKeyUuids, Pageable page);

  List<CredentialVersionData> findAllByCredentialNameUuid(UUID uuid);

  CredentialVersionData findFirstByCredentialNameUuidOrderByVersionCreatedAtDesc(UUID uuid);
}
