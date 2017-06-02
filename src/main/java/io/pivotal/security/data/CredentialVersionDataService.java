package io.pivotal.security.data;

import io.pivotal.security.domain.CredentialFactory;
import io.pivotal.security.entity.Credential;
import io.pivotal.security.entity.CredentialVersionData;
import io.pivotal.security.repository.CredentialVersionRepository;
import io.pivotal.security.service.EncryptionKeyCanaryMapper;
import io.pivotal.security.view.FindCredentialResult;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Slice;
import org.springframework.data.domain.SliceImpl;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static com.google.common.collect.Lists.newArrayList;
import static io.pivotal.security.repository.CredentialVersionRepository.BATCH_SIZE;

@Service
public class CredentialVersionDataService {

  private final CredentialVersionRepository credentialVersionRepository;
  private final CredentialDataService credentialDataService;
  private final JdbcTemplate jdbcTemplate;
  private final EncryptionKeyCanaryMapper encryptionKeyCanaryMapper;
  private final CredentialFactory credentialFactory;
  private final String findMatchingNameQuery =
      " select credential.name, credential_version.version_created_at from ("
          + "   select"
          + "     max(version_created_at) as version_created_at,"
          + "     credential_uuid"
          + "   from credential_version group by credential_uuid"
          + " ) as credential_version inner join ("
          + "   select * from credential"
          + "     where lower(name) like lower(?)"
          + " ) as credential"
          + " on credential_version.credential_uuid = credential.uuid"
          + " order by version_created_at desc";

  @Autowired
  protected CredentialVersionDataService(
      CredentialVersionRepository credentialVersionRepository,
      CredentialDataService credentialDataService,
      JdbcTemplate jdbcTemplate,
      EncryptionKeyCanaryMapper encryptionKeyCanaryMapper,
      CredentialFactory credentialFactory
  ) {
    this.credentialVersionRepository = credentialVersionRepository;
    this.credentialDataService = credentialDataService;
    this.jdbcTemplate = jdbcTemplate;
    this.encryptionKeyCanaryMapper = encryptionKeyCanaryMapper;
    this.credentialFactory = credentialFactory;
  }

  public <Z extends io.pivotal.security.domain.Credential> Z save(Z namedSecret) {
    return (Z) namedSecret.save(this);
  }

  public <Z extends io.pivotal.security.domain.Credential> Z save(CredentialVersionData credentialVersionData) {
    if (credentialVersionData.getEncryptionKeyUuid() == null) {
      credentialVersionData.setEncryptionKeyUuid(encryptionKeyCanaryMapper.getActiveUuid());
    }

    Credential credential = credentialVersionData.getCredential();

    if (credential.getUuid() == null) {
      credentialVersionData.setCredential(credentialDataService.save(credential));
    }

    return (Z) credentialFactory.makeCredentialFromEntity(credentialVersionRepository.saveAndFlush(credentialVersionData));
  }

  public List<String> findAllPaths() {
    return credentialDataService.findAll()
        .stream()
        .map(Credential::getName)
        .flatMap(CredentialVersionDataService::fullHierarchyForPath)
        .distinct()
        .sorted()
        .collect(Collectors.toList());
  }

  private static Stream<String> fullHierarchyForPath(String path) {
    String[] components = path.split("/");
    if (components.length > 1) {
      StringBuilder currentPath = new StringBuilder();
      List<String> pathSet = new ArrayList<>();
      for (int i = 0; i < components.length - 1; i++) {
        String element = components[i];
        currentPath.append(element).append('/');
        pathSet.add(currentPath.toString());
      }
      return pathSet.stream();
    } else {
      return Stream.of();
    }
  }

  public io.pivotal.security.domain.Credential findMostRecent(String name) {
    Credential credential = credentialDataService.find(name);

    if (credential == null) {
      return null;
    } else {
      return credentialFactory.makeCredentialFromEntity(credentialVersionRepository
          .findFirstByCredentialUuidOrderByVersionCreatedAtDesc(credential.getUuid()));
    }
  }

  public io.pivotal.security.domain.Credential findByUuid(String uuid) {
    return credentialFactory.makeCredentialFromEntity(credentialVersionRepository.findOneByUuid(UUID.fromString(uuid)));
  }

  public List<FindCredentialResult> findContainingName(String name) {
    return findMatchingName("%" + name + "%");
  }

  public List<FindCredentialResult> findStartingWithPath(String path) {
    path = StringUtils.prependIfMissing(path, "/");
    path = StringUtils.appendIfMissing(path, "/");

    return findMatchingName(path + "%");
  }

  public boolean delete(String name) {
    return credentialDataService.delete(name);
  }

  public List<io.pivotal.security.domain.Credential> findAllByName(String name) {
    Credential credential = credentialDataService.find(name);

    return credential != null ? credentialFactory.makeCredentialsFromEntities(credentialVersionRepository.findAllByCredentialUuid(credential.getUuid()))
        : newArrayList();
  }

  public Long count() {
    return credentialVersionRepository.count();
  }

  public Long countAllNotEncryptedByActiveKey() {
    return credentialVersionRepository.countByEncryptionKeyUuidNot(
        encryptionKeyCanaryMapper.getActiveUuid()
    );
  }

  public Long countEncryptedWithKeyUuidIn(List<UUID> uuids) {
    return credentialVersionRepository.countByEncryptionKeyUuidIn(uuids);
  }

  public Slice<io.pivotal.security.domain.Credential> findEncryptedWithAvailableInactiveKey() {
    final Slice<CredentialVersionData> credentialDataSlice = credentialVersionRepository.findByEncryptionKeyUuidIn(
        encryptionKeyCanaryMapper.getCanaryUuidsWithKnownAndInactiveKeys(),
        new PageRequest(0, BATCH_SIZE)
    );
    return new SliceImpl(credentialFactory.makeCredentialsFromEntities(credentialDataSlice.getContent()));
  }

  private List<FindCredentialResult> findMatchingName(String nameLike) {
    final List<FindCredentialResult> query = jdbcTemplate.query(
        findMatchingNameQuery,
        new Object[]{nameLike},
        (rowSet, rowNum) -> {
          final Instant versionCreatedAt = Instant
              .ofEpochMilli(rowSet.getLong("version_created_at"));
          final String name = rowSet.getString("name");
          return new FindCredentialResult(versionCreatedAt, name);
        }
    );
    return query;
  }
}
