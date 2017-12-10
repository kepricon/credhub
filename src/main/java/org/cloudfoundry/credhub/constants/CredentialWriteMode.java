package org.cloudfoundry.credhub.constants;

public enum CredentialWriteMode {
    OVERWRITE("overwrite"),
    NO_OVERWRITE("no-overwrite"),
    CONVERGE("converge");

    public final String mode;

    CredentialWriteMode(String mode) {
            this.mode = mode;
        }
}
