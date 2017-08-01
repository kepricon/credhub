package io.pivotal.security.service;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.data.CredentialDataService;
import io.pivotal.security.data.EncryptionKeyCanaryDataService;
import io.pivotal.security.domain.CertificateCredential;
import io.pivotal.security.domain.PasswordCredential;
import io.pivotal.security.domain.SshCredential;
import org.junit.runner.RunWith;
import org.springframework.data.domain.SliceImpl;

import java.util.ArrayList;
import java.util.UUID;

import static com.google.common.collect.Lists.newArrayList;
import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.it;
import static java.util.Arrays.asList;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(Spectrum.class)
public class EncryptionKeyRotatorTest {

  private CredentialDataService credentialDataService;

  private CertificateCredential certificateCredential;
  private PasswordCredential passwordCredential;
  private SshCredential sshCredential;
  private EncryptionKeyCanaryMapper encryptionKeyCanaryMapper;
  private EncryptionKeyCanaryDataService encryptionKeyCanaryDataService;
  private UUID activeUuid;
  private UUID oldUuid;

  {
    beforeEach(() -> {
      activeUuid = UUID.randomUUID();
      oldUuid = UUID.randomUUID();

      credentialDataService = mock(CredentialDataService.class);

      certificateCredential = mock(CertificateCredential.class);
      passwordCredential = mock(PasswordCredential.class);
      sshCredential = mock(SshCredential.class);

      encryptionKeyCanaryMapper =mock(EncryptionKeyCanaryMapper.class);
      when(encryptionKeyCanaryMapper.getCanaryUuidsWithKnownAndInactiveKeys())
          .thenReturn(newArrayList(oldUuid));
      encryptionKeyCanaryDataService = mock(EncryptionKeyCanaryDataService.class);
      when(credentialDataService.findEncryptedWithAvailableInactiveKey())
          .thenReturn(new SliceImpl<>(asList(certificateCredential, passwordCredential)))
          .thenReturn(new SliceImpl<>(asList(sshCredential)))
          .thenReturn(new SliceImpl<>(new ArrayList<>()));

//      when()

      final EncryptionKeyRotator encryptionKeyRotator = new EncryptionKeyRotator(credentialDataService, encryptionKeyCanaryMapper, encryptionKeyCanaryDataService);

      encryptionKeyRotator.rotate();
    });

    it("should rotate all the credentials and CAs that were encrypted with an available old key",
        () -> {
          verify(certificateCredential).rotate();
          verify(passwordCredential).rotate();
          verify(sshCredential).rotate();
        });

    it("should save all the credentials, CAs that were rotated", () -> {
      verify(credentialDataService).save(certificateCredential);
      verify(credentialDataService).save(passwordCredential);
      verify(credentialDataService).save(sshCredential);
    });

    it("deletes the unused canaries", () -> {
      verify(encryptionKeyCanaryDataService, times(0)).delete(activeUuid);
      verify(encryptionKeyCanaryDataService).delete(oldUuid);
    });
  }
}
