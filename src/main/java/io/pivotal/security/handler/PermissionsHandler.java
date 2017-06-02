package io.pivotal.security.handler;

import io.pivotal.security.auth.UserContext;
import io.pivotal.security.data.PermissionsDataService;
import io.pivotal.security.data.CredentialDataService;
import io.pivotal.security.entity.Credential;
import io.pivotal.security.exceptions.EntryNotFoundException;
import io.pivotal.security.exceptions.PermissionException;
import io.pivotal.security.request.PermissionEntry;
import io.pivotal.security.service.PermissionService;
import io.pivotal.security.view.PermissionsView;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class PermissionsHandler {
  private final PermissionService permissionService;
  private final PermissionsDataService permissionsDataService;
  private final CredentialDataService credentialDataService;

  @Autowired
  PermissionsHandler(
      PermissionService permissionService,
      PermissionsDataService permissionsDataService,
      CredentialDataService credentialDataService
  ) {
    this.permissionService = permissionService;
    this.permissionsDataService = permissionsDataService;
    this.credentialDataService = credentialDataService;
  }

  public PermissionsView getPermissions(UserContext userContext, String name) {
    try {
      final Credential credential = credentialDataService.findOrThrow(name);

      permissionService.verifyAclReadPermission(userContext, name);

      return new PermissionsView(
          credential.getName(),
          permissionsDataService.getAccessControlList(credential)
      );
    } catch (PermissionException pe){
      // lack of permissions should be indistinguishable from not found.
      throw new EntryNotFoundException("error.resource_not_found");
    }
  }

  public PermissionsView setPermissions(UserContext userContext, String name, List<PermissionEntry> permissionEntryList) {
    final Credential credential = credentialDataService.find(name);

    // We need to verify that the credential exists in case ACL enforcement is off
    if (credential == null || !permissionService.hasAclWritePermission(userContext, name)) {
      throw new EntryNotFoundException("error.acl.lacks_credential_write");
    }

    permissionsDataService
        .saveAccessControlEntries(credential, permissionEntryList);

    return new PermissionsView(credential.getName(), permissionsDataService.getAccessControlList(credential));
  }

  public void deletePermissionEntry(UserContext userContext, String credentialName, String actor) {
    if (!permissionService.hasAclWritePermission(userContext, credentialName)) {
      throw new EntryNotFoundException("error.acl.lacks_credential_write");
    }

    boolean successfullyDeleted = permissionsDataService
        .deleteAccessControlEntry(credentialName, actor);

    if (!successfullyDeleted) {
      throw new EntryNotFoundException("error.acl.lacks_credential_write");
    }
  }
}
