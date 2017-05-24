package io.pivotal.security.util;

import com.google.common.base.Charsets;
import com.google.common.io.Resources;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.URL;

@Component
public class ResourceReader {
  public String readFileToString(String filename) {
    try{
      URL resource = Resources.getResource(filename);
      return Resources.toString(resource, Charsets.UTF_8).trim();
      } catch (IOException e) {
        throw new RuntimeException(e);
    }
  }
}
