package io.pivotal.security.handler;

import io.pivotal.security.auth.UserContext;
import io.pivotal.security.data.AccessControlDataService;
import io.pivotal.security.data.CredentialNameDataService;
import io.pivotal.security.entity.AccessEntryData;
import io.pivotal.security.entity.CredentialName;
import io.pivotal.security.exceptions.EntryNotFoundException;
import io.pivotal.security.exceptions.PermissionException;
import io.pivotal.security.request.AccessControlEntry;
import io.pivotal.security.request.AccessControlOperation;
import io.pivotal.security.service.PermissionService;
import io.pivotal.security.view.AccessControlListResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.stream.Collectors;

@Component
public class AccessControlHandler {
  private final PermissionService permissionService;
  private final AccessControlDataService accessControlDataService;
  private final CredentialNameDataService credentialNameDataService;

  @Autowired
  AccessControlHandler(
      PermissionService permissionService,
      AccessControlDataService accessControlDataService,
      CredentialNameDataService credentialNameDataService
  ) {
    this.permissionService = permissionService;
    this.accessControlDataService = accessControlDataService;
    this.credentialNameDataService = credentialNameDataService;
  }

  public AccessControlListResponse getAccessControlListResponse(UserContext userContext, String name) {
    try {
      final CredentialName credentialName = credentialNameDataService.findOrThrow(name);

      permissionService.verifyAclReadPermission(userContext, name);
      List<AccessControlEntry> accessControlEntries = createViews(accessControlDataService.getAccessControlList(credentialName));
      return new AccessControlListResponse(
          credentialName.getName(),
          accessControlEntries
      );
    } catch (PermissionException pe){
      // lack of permissions should be indistinguishable from not found.
      throw new EntryNotFoundException("error.resource_not_found");
    }
  }

  public AccessControlListResponse setAccessControlEntries(UserContext userContext, String name, List<AccessControlEntry> accessControlEntryList) {
    final CredentialName credentialName = credentialNameDataService.findOrThrow(name);

    if (!permissionService.hasAclWritePermission(userContext, name)) {
      throw new PermissionException("error.acl.lacks_credential_write");
    }

    accessControlDataService
        .saveAccessControlEntries(credentialName, accessControlEntryList);

    List<AccessEntryData> accessControlList = accessControlDataService
        .getAccessControlList(credentialName);
    return new AccessControlListResponse(credentialName.getName(), createViews(accessControlList));
  }

  public void deleteAccessControlEntries(UserContext userContext, AccessEntryData accessEntryData) {
    if (!permissionService.hasAclWritePermission(userContext, accessEntryData.getCredentialName().getName())) {
      throw new EntryNotFoundException("error.acl.lacks_credential_write");
    }

    accessControlDataService.deleteAccessControlEntry(accessEntryData);
  }

  private AccessControlEntry createViewFor(AccessEntryData data) {
    if (data == null ) {
      return null;
    }
    AccessControlEntry entry = new AccessControlEntry();
    List<AccessControlOperation> operations = data.generateAccessControlOperations();
    entry.setAllowedOperations(operations);
    entry.setActor(data.getActor());
    return entry;
  }

  private List<AccessControlEntry> createViews(List<AccessEntryData> accessEntryDataList) {
    return accessEntryDataList
        .stream()
        .map(this::createViewFor)
        .collect(Collectors.toList());
  }
}
