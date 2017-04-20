package io.pivotal.security.domain;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.entity.NamedPasswordSecretData;
import io.pivotal.security.request.AccessControlEntry;
import io.pivotal.security.request.AccessControlOperation;
import io.pivotal.security.request.StringGenerationParameters;
import io.pivotal.security.service.Encryption;
import org.junit.runner.RunWith;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static com.google.common.collect.Lists.newArrayList;
import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.itThrows;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.samePropertyValuesAs;
import static org.hamcrest.core.IsNull.notNullValue;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(Spectrum.class)
public class NamedPasswordSecretTest {

  private static final List<AccessControlEntry> EMPTY_ENTRIES_LIST = new ArrayList<>();
  private static final NamedPasswordSecret NO_EXISTING_NAMED_PASSWORD_SECRET = null;
  private static final List<AccessControlEntry> NULL_ENTRIES_LIST = null;
  private static final String PASSWORD = "my-password";

  private NamedPasswordSecret subject;
  private NamedPasswordSecretData namedPasswordSecretData;
  private Encryptor encryptor;
  private UUID canaryUuid;

  private byte[] encryptedValue;
  private byte[] nonce;

  {
    beforeEach(() -> {
      canaryUuid = UUID.randomUUID();
      encryptor = mock(Encryptor.class);

      encryptedValue = "fake-encrypted-value".getBytes();
      nonce = "fake-nonce".getBytes();

      when(encryptor.encrypt(null))
          .thenReturn(new Encryption(canaryUuid, null, null));
      when(encryptor.encrypt(PASSWORD))
          .thenReturn(new Encryption(canaryUuid, encryptedValue, nonce));

      when(encryptor.decrypt(any(UUID.class), eq(encryptedValue), eq(nonce)))
          .thenReturn(PASSWORD);

      namedPasswordSecretData = new NamedPasswordSecretData("/Foo");
      subject = new NamedPasswordSecret(namedPasswordSecretData);
      subject.setEncryptor(encryptor);
    });

    it("returns type password", () -> {
      assertThat(subject.getSecretType(), equalTo("password"));
    });

    describe("#getGenerationParameters", () -> {
      beforeEach(() -> {
        subject.setPassword(PASSWORD);
        subject.getPassword();
      });

      it("should detect the parameters from the encrypted password", () -> {
        StringGenerationParameters expected = new StringGenerationParameters();

        expected.setLength(PASSWORD.length());
        expected.setExcludeUpper(true);
        expected.setExcludeNumber(true);
        expected.setIncludeSpecial(true);

        assertThat(subject.getGenerationParameters(), samePropertyValuesAs(expected));
      });
    });

    describe("#getPassword", () -> {
      beforeEach(() -> {
        subject = new NamedPasswordSecret("/Foo");
        subject.setEncryptor(encryptor);
        when(encryptor.encrypt(null))
            .thenReturn(new Encryption(canaryUuid, null, null));
        subject.setPassword(PASSWORD);
        subject.getGenerationParameters();
      });

      it("should call decrypt twice: once for password and once for parameters", () -> {
        subject.getPassword();

        verify(encryptor, times(1)).decrypt(any(), any(), any());
      });
    });

    describe("#setPassword", () -> {
      it("sets the nonce and the encrypted value", () -> {
        subject.setPassword(PASSWORD);
        assertThat(namedPasswordSecretData.getEncryptedValue(), notNullValue());
        assertThat(namedPasswordSecretData.getNonce(), notNullValue());
      });

      it("can decrypt values", () -> {
        subject.setPassword(PASSWORD);

        assertThat(subject.getPassword(), equalTo(PASSWORD));
      });

      itThrows("when setting a value that is null", IllegalArgumentException.class, () -> {
        subject.setPassword(null);
      });
    });

    describe("#createNewVersion", () -> {
      beforeEach(() -> {
        namedPasswordSecretData = new NamedPasswordSecretData("/existingName");
        namedPasswordSecretData.setEncryptedValue("old-encrypted-value".getBytes());
        namedPasswordSecretData.setNonce("old-nonce".getBytes());
        subject = new NamedPasswordSecret(namedPasswordSecretData);
        subject.setEncryptor(encryptor);

        ArrayList<AccessControlOperation> operations = newArrayList(AccessControlOperation.READ,
            AccessControlOperation.WRITE);
        List<AccessControlEntry> accessControlEntries = newArrayList(
            new AccessControlEntry("Bob", operations));
        subject.setAccessControlList(accessControlEntries);
      });

      it("copies values from existing, except password", () -> {
        NamedPasswordSecret newSecret = NamedPasswordSecret
            .createNewVersion(subject, "anything I AM IGNORED", PASSWORD,
                encryptor, EMPTY_ENTRIES_LIST);

        assertThat(newSecret.getName(), equalTo("/existingName"));
        assertThat(newSecret.getPassword(), equalTo(PASSWORD));
      });

      it("creates new if no existing", () -> {
        NamedPasswordSecret newSecret = NamedPasswordSecret.createNewVersion(
            NO_EXISTING_NAMED_PASSWORD_SECRET,
            "/newName",
            PASSWORD,
            encryptor,
            EMPTY_ENTRIES_LIST);

        assertThat(newSecret.getName(), equalTo("/newName"));
        assertThat(newSecret.getPassword(), equalTo(PASSWORD));
      });

      it("ignores ACEs if not provided", () -> {
        NamedPasswordSecret newSecret = NamedPasswordSecret
            .createNewVersion(subject, "anything I AM IGNORED", PASSWORD,
                encryptor, NULL_ENTRIES_LIST);
        assertThat(newSecret.getSecretName().getAccessControlList(), hasSize(0));
      });
    });
  }
}
