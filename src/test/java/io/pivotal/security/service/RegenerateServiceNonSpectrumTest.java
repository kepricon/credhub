package io.pivotal.security.service;

import io.pivotal.security.audit.EventAuditRecordParameters;
import io.pivotal.security.auth.UserContext;
import io.pivotal.security.credential.CredentialValue;
import io.pivotal.security.data.CredentialDataService;
import io.pivotal.security.domain.Credential;
import io.pivotal.security.request.PermissionEntry;
import io.pivotal.security.request.StringGenerationParameters;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.util.ArrayList;
import java.util.Collections;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyList;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(JUnit4.class)
public class RegenerateServiceNonSpectrumTest {
  private RegenerateService subject;

  private CredentialDataService credentialDataService;
  private CredentialService credentialService;
  private GeneratorService generatorService;

  @Before
  public void beforeEach() {
    credentialDataService = mock(CredentialDataService.class);
    credentialService = mock(CredentialService.class);
    generatorService = mock(GeneratorService.class);

    subject = new RegenerateService(credentialDataService, credentialService, generatorService);
  }

  @Test
  public void performRegenerateBySigner_regeneratesCertificatesSignedByGivenSigner(){
    when(credentialDataService.findAllCertificateCredentialsByCaName("/some-signer-name")).thenReturn(
        Collections.singletonList("cert1"));

    Credential credential = mock(Credential.class);

    when(credentialDataService.findMostRecent("cert1")).thenReturn(credential);

    subject.performRegenerateBySigner("/some-signer-name", mock(UserContext.class),
        mock(PermissionEntry.class), new ArrayList<EventAuditRecordParameters>());

    verify(credentialService).save(eq("cert1"), eq("certificate"), any(CredentialValue.class), any(
        StringGenerationParameters.class), anyList(), eq(true), any(UserContext.class), any(PermissionEntry.class), anyList());
  }
}
