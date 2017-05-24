package io.pivotal.security.config;


import io.pivotal.security.util.ResourceReader;
import org.springframework.stereotype.Component;

@Component
public class VersionProvider {

  private ResourceReader resources;

  public VersionProvider(ResourceReader resources){
    this.resources = resources;
  }

  public String currentVersion() {
      return resources.readFileToString("version");
  }
}
