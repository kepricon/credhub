package io.pivotal.security.generator;

import io.pivotal.security.credential.CertificateCredentialValue;
import io.pivotal.security.data.CertificateAuthorityService;
import io.pivotal.security.domain.CertificateParameters;
import io.pivotal.security.request.BaseCredentialGenerateRequest;
import io.pivotal.security.request.CertificateGenerateRequest;
import io.pivotal.security.request.CertificateGenerationParameters;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.security.KeyPair;
import java.security.cert.X509Certificate;

import static io.pivotal.security.util.CertificateFormatter.pemOf;

@Component
public class CertificateGenerator implements
    CredentialGenerator<CertificateParameters, CertificateCredentialValue> {

  private final LibcryptoRsaKeyPairGenerator keyGenerator;
  private final SignedCertificateGenerator signedCertificateGenerator;
  private final CertificateAuthorityService certificateAuthorityService;


  @Autowired
  public CertificateGenerator(
      LibcryptoRsaKeyPairGenerator keyGenerator,
      SignedCertificateGenerator signedCertificateGenerator,
      CertificateAuthorityService certificateAuthorityService
  ) {
    this.keyGenerator = keyGenerator;
    this.signedCertificateGenerator = signedCertificateGenerator;
    this.certificateAuthorityService = certificateAuthorityService;
  }

  @Override
  public CertificateCredentialValue generateCredential(CertificateParameters params) {
    try {
      KeyPair keyPair = keyGenerator.generateKeyPair(params.getKeyLength());
      X509Certificate cert;
      String caName = null;
      String caCertificate = null;
      String privatePem = pemOf(keyPair.getPrivate());

      if (params.isSelfSigned()) {
        cert = signedCertificateGenerator.getSelfSigned(keyPair, params);
      } else {
        CertificateCredentialValue ca = certificateAuthorityService
            .findMostRecent(params.getCaName());
        caCertificate = ca.getCertificate();
        caName = params.getCaName();
        cert = signedCertificateGenerator.getSignedByIssuer(keyPair, params, ca);
      }

      return new CertificateCredentialValue(caCertificate, pemOf(cert), privatePem, caName);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  @Override
  public CertificateCredentialValue generateCredential(BaseCredentialGenerateRequest requestBody) {
    final CertificateGenerateRequest certificateRequest = (CertificateGenerateRequest) requestBody;
    if (certificateRequest.getCertificateParameters() == null) {
      final CertificateGenerationParameters certificateGenerationParameters = certificateRequest
          .getGenerationParameters();
      return this.generateCredential(new CertificateParameters(certificateGenerationParameters));
    } else {
      return this.generateCredential(certificateRequest.getCertificateParameters());
    }
  }
}
