package io.pivotal.security.request;

import com.fasterxml.jackson.annotation.JsonAutoDetect;

@JsonAutoDetect
@SuppressWarnings("unused")
public class RegenerateRequest {

  private String name;

  private String signedBy;

  public RegenerateRequest() {
        /* this needs to be there for jackson to be happy */
  }

  public RegenerateRequest(String name, String signedBy) {
    this.name = name;
    this.signedBy = signedBy;
  }

  public String getName() {
    return name;
  }

  public void setName(String name) {
    this.name = name;
  }

  public String getSignedBy() {
    return signedBy;
  }

  public void setSignedBy(String signedBy) {
    this.signedBy = signedBy;
  }
}
