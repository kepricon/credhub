package io.pivotal.security.data;

import io.pivotal.security.entity.AccessEntryData;
import io.pivotal.security.entity.CredentialName;
import io.pivotal.security.repository.AccessEntryRepository;
import io.pivotal.security.request.AccessControlEntry;
import io.pivotal.security.request.AccessControlOperation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Optional;

@Component
public class AccessControlDataService {

  private AccessEntryRepository accessEntryRepository;
  private final CredentialNameDataService credentialNameDataService;

  @Autowired
  public AccessControlDataService(
      AccessEntryRepository accessEntryRepository,
      CredentialNameDataService credentialNameDataService
  ) {
    this.accessEntryRepository = accessEntryRepository;
    this.credentialNameDataService = credentialNameDataService;
  }

  public List<AccessEntryData> getAccessControlList(String name) {
    return getAccessControlList(credentialNameDataService.findOrThrow(name));
  }

  public List<AccessEntryData> getAccessControlList(CredentialName credentialName) {
    return accessEntryRepository.findAllByCredentialNameUuid(credentialName.getUuid());
  }

  public List<AccessEntryData> saveAccessControlEntries(
      CredentialName credentialName,
      List<AccessControlEntry> entries
  ) {
    List<AccessEntryData> existingAccessEntries = accessEntryRepository
        .findAllByCredentialNameUuid(credentialName.getUuid());

    for (AccessControlEntry ace : entries) {
      upsertAccessEntryOperations(credentialName, existingAccessEntries, ace.getActor(),
          ace.getAllowedOperations());
    }
    return getAccessControlList(credentialName);
  }

  public AccessEntryData getAccessControlEntry(String actor, String name) {
    CredentialName credentialName = credentialNameDataService.findOrThrow(name);
    return accessEntryRepository.findByCredentialNameUuidAndActor(credentialName.getUuid(), actor);
  }

  public void deleteAccessControlEntry(AccessEntryData accessEntryData) {
    accessEntryRepository.delete(accessEntryData);
  }

  public boolean hasReadAclPermission(String actor, String name) {
    CredentialName credentialName = credentialNameDataService.find(name);
    if (credentialName != null) {
      final AccessEntryData accessEntryData =
          accessEntryRepository.findByCredentialNameUuidAndActor(credentialName.getUuid(), actor);
      return accessEntryData != null && accessEntryData.hasReadAclPermission();
    }
    return false;
  }

  public boolean hasAclWritePermission(String actor, String name) {
    CredentialName credentialName = credentialNameDataService.find(name);
    if (credentialName != null) {
      final AccessEntryData accessEntryData =
          accessEntryRepository.findByCredentialNameUuidAndActor(credentialName.getUuid(), actor);
      return accessEntryData != null && accessEntryData.hasWriteAclPermission();
    }
    return false;
  }

  public boolean hasReadPermission(String actor, String name) {
    CredentialName credentialName = credentialNameDataService.find(name);
    if (credentialName != null) {
      AccessEntryData accessEntryData =
          accessEntryRepository.findByCredentialNameUuidAndActor(credentialName.getUuid(), actor);
      return accessEntryData != null && accessEntryData.hasReadPermission();
    }
    return false;
  }

  public boolean hasCredentialWritePermission(String actor, String name) {
    CredentialName credentialName = credentialNameDataService.find(name);
    AccessEntryData accessEntryData =
        accessEntryRepository.findByCredentialNameUuidAndActor(credentialName.getUuid(), actor);
    return accessEntryData != null && accessEntryData.hasWritePermission();
  }

  public boolean hasCredentialDeletePermission(String actor, String name) {
    CredentialName credentialName = credentialNameDataService.find(name);
    AccessEntryData accessEntryData =
        accessEntryRepository.findByCredentialNameUuidAndActor(credentialName.getUuid(), actor);
    return accessEntryData != null && accessEntryData.hasDeletePermission();
  }

  private void upsertAccessEntryOperations(CredentialName credentialName,
      List<AccessEntryData> accessEntries, String actor, List<AccessControlOperation> operations) {
    AccessEntryData entry = findAccessEntryForActor(accessEntries, actor);

    if (entry == null) {
      entry = new AccessEntryData(credentialName, actor);
    }

    entry.enableOperations(operations);
    accessEntryRepository.saveAndFlush(entry);
  }

  private AccessEntryData findAccessEntryForActor(List<AccessEntryData> accessEntries,
      String actor) {
    Optional<AccessEntryData> temp = accessEntries.stream()
        .filter(accessEntryData -> accessEntryData.getActor().equals(actor))
        .findFirst();
    return temp.orElse(null);
  }
}
