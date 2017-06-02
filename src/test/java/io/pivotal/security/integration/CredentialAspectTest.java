package io.pivotal.security.integration;

import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.data.CredentialDataService;
import io.pivotal.security.entity.Credential;
import io.pivotal.security.util.DatabaseProfileResolver;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.transaction.annotation.Transactional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.core.IsNull.notNullValue;

@RunWith(SpringRunner.class)
@ActiveProfiles(profiles = {"unit-test"}, resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
@Transactional
public class CredentialAspectTest {
  @Autowired
  CredentialDataService credentialDataService;

  @Before
  public void setup() {
    credentialDataService.save(new Credential("/test/name"));
  }

  @Test
  public void save_prependsLeadingSlashToCredentialNameIfMissing() {
    Credential savedCredential = credentialDataService
        .save(new Credential("new/name"));
    assertThat(savedCredential.getName(), equalTo("/new/name"));
  }

  @Test
  public void saveAndFlush_prependsLeadingSlashToCredentialNameIfMissing() {
    Credential savedCredential = credentialDataService.save(new Credential("new/name"));
    assertThat(savedCredential.getName(), equalTo("/new/name"));
  }

  @Test
  public void findOneByNameIgnoreCase_prependsLeadingSlashToCredentialNameIfMissing() {
    Credential foundCredential = credentialDataService.find("test/name");
    assertThat(foundCredential, notNullValue());
    assertThat(foundCredential.getName(), equalTo("/test/name"));
  }

  @Test
  public void deleteByNameIgnoreCase_prependsLeadingSlashToCredentialNameIfMissing() {
    boolean deleted = credentialDataService.delete("test/name");
    assertThat(deleted, equalTo(true));
  }
}
