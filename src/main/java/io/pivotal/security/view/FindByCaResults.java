package io.pivotal.security.view;

import org.codehaus.jackson.annotate.JsonAutoDetect;

import java.util.Set;

@JsonAutoDetect
public class FindByCaResults {
  private Set<String> credentials;

  public FindByCaResults() {
  }

  public Set<String> getCredentials() {
    return credentials;
  }

  public void setCredentials(Set<String> credentials) {
    this.credentials = credentials;
  }
}
