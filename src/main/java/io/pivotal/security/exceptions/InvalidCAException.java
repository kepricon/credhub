package io.pivotal.security.exceptions;

public class InvalidCAException  extends RuntimeException {
    public InvalidCAException(String message) {
      super(message);
    }

}
