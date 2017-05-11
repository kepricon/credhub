package io.pivotal.security.audit;

import io.pivotal.security.entity.AccessEntryData;
import io.pivotal.security.request.AccessControlEntry;
import io.pivotal.security.request.AccessControlOperation;

import java.util.List;

import static com.google.common.collect.Lists.newArrayList;
import static java.util.Collections.singletonList;

public class EventAuditRecordParametersFactory {
  public static List<EventAuditRecordParameters> createPermissionEventAuditRecordParameters(
      AuditingOperationCode auditingOperationCode,
      String credentialName,
      AccessEntryData accessControlEntry
  ) {
    return createPermissionsEventAuditParameters(
        auditingOperationCode,
        credentialName,
        singletonList(createViewFor(accessControlEntry))
    );
  }

  public static List<EventAuditRecordParameters> createPermissionsEventAuditParameters(
      AuditingOperationCode auditingOperationCode,
      String credentialName,
      List<AccessControlEntry> accessControlEntries
  ) {
    List<EventAuditRecordParameters> eventAuditRecordParameters = newArrayList();
    accessControlEntries.stream()
        .forEach(entry -> {
          String actor = entry.getActor();
          entry.getAllowedOperations().stream()
              .forEach(operation -> {
                eventAuditRecordParameters.add(new EventAuditRecordParameters(
                    auditingOperationCode,
                    credentialName,
                    operation,
                    actor));
              });
        });
    return eventAuditRecordParameters;
  }

  private static AccessControlEntry createViewFor(AccessEntryData data) {
    if (data == null ) {
      return null;
    }
    AccessControlEntry entry = new AccessControlEntry();
    List<AccessControlOperation> operations = data.generateAccessControlOperations();
    entry.setAllowedOperations(operations);
    entry.setActor(data.getActor());
    return entry;
  }
}
