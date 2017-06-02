package io.pivotal.security.service;

import io.pivotal.security.audit.AuditingOperationCode;
import io.pivotal.security.audit.EventAuditRecordParameters;
import io.pivotal.security.auth.UserContext;
import io.pivotal.security.constants.CredentialType;
import io.pivotal.security.credential.CredentialValue;
import io.pivotal.security.data.PermissionsDataService;
import io.pivotal.security.data.CredentialVersionDataService;
import io.pivotal.security.domain.Credential;
import io.pivotal.security.domain.CredentialFactory;
import io.pivotal.security.exceptions.ParameterizedValidationException;
import io.pivotal.security.request.PermissionEntry;
import io.pivotal.security.request.StringGenerationParameters;
import io.pivotal.security.view.CredentialView;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

import static io.pivotal.security.audit.AuditingOperationCode.ACL_UPDATE;
import static io.pivotal.security.audit.AuditingOperationCode.CREDENTIAL_ACCESS;
import static io.pivotal.security.audit.AuditingOperationCode.CREDENTIAL_UPDATE;
import static io.pivotal.security.audit.EventAuditRecordParametersFactory.createPermissionsEventAuditParameters;

@Service
public class CredentialService {

  private final CredentialVersionDataService credentialVersionDataService;
  private final PermissionsDataService permissionsDataService;
  private PermissionService permissionService;
  private final CredentialFactory credentialFactory;

  @Autowired
  public CredentialService(
      CredentialVersionDataService credentialVersionDataService,
      PermissionsDataService permissionsDataService,
      PermissionService permissionService,
      CredentialFactory credentialFactory
  ) {
    this.credentialVersionDataService = credentialVersionDataService;
    this.permissionsDataService = permissionsDataService;
    this.permissionService = permissionService;
    this.credentialFactory = credentialFactory;
  }

  public CredentialView save(
      UserContext userContext,
      List<EventAuditRecordParameters> parametersList,
      String credentialName,
      boolean isOverwrite,
      String type,
      StringGenerationParameters generationParameters,
      CredentialValue credentialValue,
      List<PermissionEntry> accessControlEntries,
      PermissionEntry currentUserPermissionEntry) {
    Credential existingCredential = credentialVersionDataService.findMostRecent(credentialName);

    boolean shouldWriteNewEntity = existingCredential == null || isOverwrite;

    AuditingOperationCode credentialOperationCode =
        shouldWriteNewEntity ? CREDENTIAL_UPDATE : CREDENTIAL_ACCESS;
    parametersList
        .add(new EventAuditRecordParameters(credentialOperationCode, credentialName));

    if (existingCredential != null) {
      permissionService
          .verifyCredentialWritePermission(userContext, credentialName);
    }

    if (existingCredential != null && !existingCredential.getCredentialType().equals(type)) {
      throw new ParameterizedValidationException("error.type_mismatch");
    }

    Credential storedCredentialVersion = existingCredential;
    if (shouldWriteNewEntity) {
      if (existingCredential == null) {
        accessControlEntries.add(currentUserPermissionEntry);
      }

      Credential newVersion = credentialFactory.makeNewCredentialVersion(
          CredentialType.valueOf(type),
          credentialName,
          credentialValue,
          existingCredential,
          generationParameters);
      storedCredentialVersion = credentialVersionDataService.save(newVersion);

      permissionsDataService.saveAccessControlEntries(
          storedCredentialVersion.getCredentialName(),
          accessControlEntries);
      parametersList.addAll(createPermissionsEventAuditParameters(
          ACL_UPDATE,
          storedCredentialVersion.getName(),
          accessControlEntries
      ));
    }

    return CredentialView.fromEntity(storedCredentialVersion);
  }
}
