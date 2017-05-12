package io.pivotal.security.domain;

import io.pivotal.security.request.CertificateGenerationParameters;
import io.pivotal.security.util.CertificateReader;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;

public class CertificateParameters {

  private int keyLength;
  private int duration;
  private boolean selfSigned = false;
  private String caName;
  private boolean isCa = false;

  private X500Name x500Name;
  private GeneralNames alternativeNames;

  private ExtendedKeyUsage extendedKeyUsage;

  private KeyUsage keyUsage;

  public CertificateParameters(CertificateGenerationParameters generationParameters) {
    this.keyUsage = buildKeyUsage(generationParameters);
    this.x500Name = buildDn(generationParameters);
    this.alternativeNames = buildAlternativeNames(generationParameters);
    this.extendedKeyUsage = buildExtendedKeyUsage(generationParameters);
    this.caName = generationParameters.getCaName();
    this.selfSigned = generationParameters.isSelfSigned();
    this.duration = generationParameters.getDuration();
    this.keyLength = generationParameters.getKeyLength();
    this.isCa = generationParameters.isCa();
  }


  public CertificateParameters(CertificateReader certificateReader, String caName){
    this.keyUsage = certificateReader.getKeyUsage();
    this.x500Name = certificateReader.getSubjectName();
    this.alternativeNames = certificateReader.getAlternativeNames();
    this.extendedKeyUsage = certificateReader.getExtendedKeyUsage();
    this.caName = caName;
    this.selfSigned = certificateReader.isSelfSigned();
    this.duration = certificateReader.getDurationDays();
    this.keyLength = certificateReader.getKeyLength();
    this.isCa = certificateReader.isCa();
  }

  public int getKeyLength() {
    return keyLength;
  }

  public int getDuration() {
    return duration;
  }

  public String getCaName() {
    return caName;
  }

  public boolean isSelfSigned() {
    return selfSigned;
  }

  public boolean isCa() {
    return isCa;
  }

  public X500Name getX500Name() {
    return x500Name;
  }

  public GeneralNames getAlternativeNames() {
    return alternativeNames;
  }

  public ExtendedKeyUsage getExtendedKeyUsage() {
    return extendedKeyUsage;
  }

  public KeyUsage getKeyUsage() {
    return keyUsage;
  }

  private KeyUsage buildKeyUsage(CertificateGenerationParameters keyUsageList) {
    return keyUsageList.getKeyUsage();
  }

  private X500Name buildDn(CertificateGenerationParameters params) {
    return params.getDn();
  }

  private GeneralNames buildAlternativeNames(CertificateGenerationParameters params) {
    return params.getAlternativeNames();
  }

  private ExtendedKeyUsage buildExtendedKeyUsage(CertificateGenerationParameters params) {
    return params.getExtendedKeyUsage();
  }
}
