package io.pivotal.security.request;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.common.net.InetAddresses;
import com.google.common.net.InternetDomainName;
import io.pivotal.security.exceptions.ParameterizedValidationException;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.GeneralNamesBuilder;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.springframework.util.StringUtils;

import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

import static com.fasterxml.jackson.annotation.JsonInclude.Include.NON_DEFAULT;
import static org.apache.commons.lang3.StringUtils.isEmpty;

@JsonInclude(NON_DEFAULT)
public class CertificateGenerationParameters {

  public static final String SERVER_AUTH = "server_auth";
  public static final String CLIENT_AUTH = "client_auth";
  public static final String CODE_SIGNING = "code_signing";
  public static final String EMAIL_PROTECTION = "email_protection";
  public static final String TIMESTAMPING = "timestamping";
  public static final String DIGITAL_SIGNATURE = "digital_signature";
  public static final String NON_REPUDIATION = "non_repudiation";
  public static final String KEY_ENCIPHERMENT = "key_encipherment";
  public static final String DATA_ENCIPHERMENT = "data_encipherment";
  public static final String KEY_AGREEMENT = "key_agreement";
  public static final String KEY_CERT_SIGN = "key_cert_sign";
  public static final String CRL_SIGN = "crl_sign";
  public static final String ENCIPHER_ONLY = "encipher_only";
  public static final String DECIPHER_ONLY = "decipher_only";

  // Parameters used in RDN; at least one must be set
  private String organization;

  private String state;

  private String country;
  private String commonName;
  private String organizationUnit;
  private String locality;
  // Optional Certificate Parameters (not used in RDN)
  private int keyLength = 2048;

  private int duration = 365;
  private boolean selfSigned = false;
  private String caName;
  private boolean isCa = false;
  private String[] alternativeNames;

  private String[] extendedKeyUsage;
  private String[] keyUsage;
  private List<Integer> validKeyLengths = Arrays.asList(2048, 3072, 4096);
  private static final Pattern DNS_WILDCARD_PATTERN = Pattern
      .compile("^\\*?(?:\\.[a-zA-Z0-9\\-]+)*$");

  private List<String> validExtendedKeyUsages = Arrays
      .asList(SERVER_AUTH, CLIENT_AUTH, CODE_SIGNING, EMAIL_PROTECTION, TIMESTAMPING);

  private List<String> validKeyUsages = Arrays
      .asList(DIGITAL_SIGNATURE, NON_REPUDIATION, KEY_ENCIPHERMENT, DATA_ENCIPHERMENT,
          KEY_AGREEMENT, KEY_CERT_SIGN, CRL_SIGN, ENCIPHER_ONLY, DECIPHER_ONLY);

  private int TEN_YEARS = 3650;
  private int ONE_DAY = 1;

  public CertificateGenerationParameters() {
  }

  public CertificateGenerationParameters setCommonName(String commonName) {
    this.commonName = commonName;
    return this;
  }

  public CertificateGenerationParameters setOrganization(String organization) {
    this.organization = organization;
    return this;
  }

//  public CertificateGenerationParameters setOrganizationUnit(String organizationUnit) {
//    this.organizationUnit = organizationUnit;
//    return this;
//  }
//
//  public CertificateGenerationParameters setLocality(String locality) {
//    this.locality = locality;
//    return this;
//  }

  public CertificateGenerationParameters setState(String state) {
    this.state = state;
    return this;
  }

  public CertificateGenerationParameters setCountry(String country) {
    this.country = country;
    return this;
  }

  public int getKeyLength() {
    return keyLength;
  }

  public CertificateGenerationParameters setKeyLength(int keyLength) {
    this.keyLength = keyLength;
    return this;
  }

  public int getDuration() {
    return duration;
  }

  public CertificateGenerationParameters setDuration(int duration) {
    this.duration = duration;
    return this;
  }


  public String getCaName() {
    return caName;
  }

  @JsonProperty("ca")
  public CertificateGenerationParameters setCaName(String caName) {
    this.caName = caName;
    return this;
  }

  public boolean isSelfSigned() {
    return selfSigned;
  }

  @JsonProperty("self_sign")
  public CertificateGenerationParameters setSelfSigned(boolean selfSigned) {
    this.selfSigned = selfSigned;
    return this;
  }

  public boolean isCa() {
    return isCa;
  }

  public CertificateGenerationParameters setIsCa(boolean isCa) {
    this.isCa = isCa;
    return this;
  }

  public CertificateGenerationParameters setAlternativeNames(String[] alternativeNames) {
    this.alternativeNames = alternativeNames;
    return this;
  }

  public CertificateGenerationParameters setExtendedKeyUsage(String[] extendedKeyUsage) {
    this.extendedKeyUsage = extendedKeyUsage;
    return this;
  }

  @JsonIgnore
  public KeyUsage getKeyUsage() {
    if (keyUsage == null){
      return null;
    }

    int bitmask = 0;

    for (String key : keyUsage) {
      switch (key) {
        case DIGITAL_SIGNATURE:
          bitmask |= org.bouncycastle.asn1.x509.KeyUsage.digitalSignature;
          break;
        case NON_REPUDIATION:
          bitmask |= org.bouncycastle.asn1.x509.KeyUsage.nonRepudiation;
          break;
        case KEY_ENCIPHERMENT:
          bitmask |= org.bouncycastle.asn1.x509.KeyUsage.keyEncipherment;
          break;
        case DATA_ENCIPHERMENT:
          bitmask |= org.bouncycastle.asn1.x509.KeyUsage.dataEncipherment;
          break;
        case KEY_AGREEMENT:
          bitmask |= org.bouncycastle.asn1.x509.KeyUsage.keyAgreement;
          break;
        case KEY_CERT_SIGN:
          bitmask |= org.bouncycastle.asn1.x509.KeyUsage.keyCertSign;
          break;
        case CRL_SIGN:
          bitmask |= org.bouncycastle.asn1.x509.KeyUsage.cRLSign;
          break;
        case ENCIPHER_ONLY:
          bitmask |= org.bouncycastle.asn1.x509.KeyUsage.encipherOnly;
          break;
        case DECIPHER_ONLY:
          bitmask |= org.bouncycastle.asn1.x509.KeyUsage.decipherOnly;
          break;
        default:
          throw new ParameterizedValidationException("error.invalid_key_usage", key);
      }
    }

    return new KeyUsage(bitmask);
  }

  public CertificateGenerationParameters setKeyUsage(String[] keyUsage) {
    this.keyUsage = keyUsage;
    return this;
  }

  @JsonIgnore
  public X500Name getDn() {
    X500NameBuilder builder = new X500NameBuilder();

    if (!StringUtils.isEmpty(organization)) {
      builder.addRDN(BCStyle.O, organization);
    }
    if (!StringUtils.isEmpty(state)) {
      builder.addRDN(BCStyle.ST, state);
    }
    if (!StringUtils.isEmpty(country)) {
      builder.addRDN(BCStyle.C, country);
    }
    if (!StringUtils.isEmpty(commonName)) {
      builder.addRDN(BCStyle.CN, commonName);
    }
    if (!StringUtils.isEmpty(organizationUnit)) {
      builder.addRDN(BCStyle.OU, organizationUnit);
    }
    if (!StringUtils.isEmpty(locality)) {
      builder.addRDN(BCStyle.L, locality);
    }

    return builder.build();
  }

  @JsonIgnore
  public GeneralNames getAlternativeNames() {
    if (this.alternativeNames == null){
      return null;
    }

    GeneralNamesBuilder builder = new GeneralNamesBuilder();

    for (String name: this.alternativeNames) {
      if (InetAddresses.isInetAddress(name)) {
        builder.addName(new GeneralName(GeneralName.iPAddress, name));
      } else  {
        builder.addName(new GeneralName(GeneralName.dNSName, name));
      }
    }

    return builder.build();
  }

  @JsonIgnore
  public ExtendedKeyUsage getExtendedKeyUsage() {
    if (extendedKeyUsage == null){
      return null;
    }
    KeyPurposeId[] keyPurposeIds = new KeyPurposeId[extendedKeyUsage.length];
    for (int i = 0; i < extendedKeyUsage.length; i++) {
      switch (extendedKeyUsage[i]) {
        case SERVER_AUTH:
          keyPurposeIds[i] = KeyPurposeId.id_kp_serverAuth;
          break;
        case CLIENT_AUTH:
          keyPurposeIds[i] = KeyPurposeId.id_kp_clientAuth;
          break;
        case CODE_SIGNING:
          keyPurposeIds[i] = KeyPurposeId.id_kp_codeSigning;
          break;
        case EMAIL_PROTECTION:
          keyPurposeIds[i] = KeyPurposeId.id_kp_emailProtection;
          break;
        case TIMESTAMPING:
          keyPurposeIds[i] = KeyPurposeId.id_kp_timeStamping;
          break;
        default:
          throw new ParameterizedValidationException("error.invalid_extended_key_usage", extendedKeyUsage[i]);
      }
    }
    return new ExtendedKeyUsage(keyPurposeIds);
  }

  public void validate() {
    if (isCa() && isEmpty(caName)) {
      selfSigned = true;
    }

    if (StringUtils.isEmpty(organization)
        && StringUtils.isEmpty(state)
        && StringUtils.isEmpty(locality)
        && StringUtils.isEmpty(organizationUnit)
        && StringUtils.isEmpty(commonName)
        && StringUtils.isEmpty(country)) {
      throw new ParameterizedValidationException("error.missing_certificate_parameters");
    } else if (StringUtils.isEmpty(caName) && !selfSigned && !isCa) {
      throw new ParameterizedValidationException("error.missing_signing_ca");
    } else if (!StringUtils.isEmpty(caName) && selfSigned) {
      throw new ParameterizedValidationException("error.ca_and_self_sign");
    }

    if (!validKeyLengths.contains(keyLength)) {
      throw new ParameterizedValidationException("error.invalid_key_length");
    }

    if (alternativeNames != null) {
      for (String name : alternativeNames) {
        if (!InetAddresses.isInetAddress(name) && !(InternetDomainName.isValid(name)
            || DNS_WILDCARD_PATTERN.matcher(name).matches())) {
          throw new ParameterizedValidationException("error.invalid_alternate_name");
        }
      }
    }

    if (extendedKeyUsage != null) {
      for (String extendedKey : extendedKeyUsage) {
        if (!validExtendedKeyUsages.contains(extendedKey)) {
          throw new ParameterizedValidationException("error.invalid_extended_key_usage",
              extendedKey);
        }
      }
    }

    if (keyUsage != null) {
      for (String keyUse : keyUsage) {
        if (!validKeyUsages.contains(keyUse)) {
          throw new ParameterizedValidationException("error.invalid_key_usage",
              keyUse);
        }
      }
    }

    if (duration < ONE_DAY || duration > TEN_YEARS) {
      throw new ParameterizedValidationException("error.invalid_duration");
    }
  }
}
