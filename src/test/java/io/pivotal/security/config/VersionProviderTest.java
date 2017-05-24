package io.pivotal.security.config;

import io.pivotal.security.util.ResourceReader;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.test.context.junit4.SpringRunner;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(SpringRunner.class)
public class VersionProviderTest {

  @Test
  public void versionProvider_readsFromStaticVersionFile() throws Exception{
    ResourceReader resourceReader = mock(ResourceReader.class);
    when(resourceReader.readFileToString("version")).thenReturn("test version");

    VersionProvider versionProvider = new VersionProvider(resourceReader);
    assertThat(versionProvider.currentVersion(), equalTo("test version"));
  }

}