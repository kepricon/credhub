package io.pivotal.security.request;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.util.List;
import java.util.Set;
import javax.validation.ConstraintViolation;

import static com.google.common.collect.Lists.newArrayList;
import static io.pivotal.security.helper.JsonTestHelper.deserialize;
import static io.pivotal.security.helper.JsonTestHelper.hasViolationWithMessage;
import static io.pivotal.security.helper.JsonTestHelper.serialize;
import static io.pivotal.security.helper.JsonTestHelper.validate;
import static org.hamcrest.CoreMatchers.allOf;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.hasProperty;
import static org.hamcrest.core.IsCollectionContaining.hasItems;
import static org.hamcrest.core.IsEqual.equalTo;

@RunWith(JUnit4.class)
public class PermissionsRequestTest {
  @Test
  public void validation_allowsGoodJson() {
    List<PermissionEntry> entryList = newArrayList(
        new PermissionEntry("someone", newArrayList(PermissionOperation.READ)));
    PermissionsRequest original = new PermissionsRequest("test-name", entryList);
    byte[] json = serialize(original);
    PermissionsRequest actual = deserialize(json, PermissionsRequest.class);

    assertThat(actual.getCredentialName(), equalTo("/test-name"));
    assertThat(actual.getPermissions(), contains(
        allOf(
            hasProperty("actor", equalTo("someone")),
            hasProperty("allowedOperations", hasItems(PermissionOperation.READ))
        )
    ));
  }

  @Test
  public void validation_ensuresCredentialNameIsNotNull() {
    List<PermissionEntry> entryList = newArrayList(
        new PermissionEntry("someone", newArrayList(PermissionOperation.READ)));
    PermissionsRequest original = new PermissionsRequest(null, entryList);
    Set<ConstraintViolation<PermissionsRequest>> violations = validate(original);

    assertThat(violations.size(), equalTo(1));
    assertThat(violations, contains(hasViolationWithMessage("error.missing_name")));
  }

  @Test
  public void validation_ensuresCredentialNameIsNotEmpty() {
    List<PermissionEntry> entryList = newArrayList(
        new PermissionEntry("someone", newArrayList(PermissionOperation.READ)));
    PermissionsRequest original = new PermissionsRequest("", entryList);
    Set<ConstraintViolation<PermissionsRequest>> violations = validate(original);

    assertThat(violations.size(), equalTo(1));
    assertThat(violations, contains(hasViolationWithMessage("error.missing_name")));
  }

  @Test
  public void validation_ensuresOperationsIsNotNull() {
    PermissionsRequest original = new PermissionsRequest("foo", null);
    Set<ConstraintViolation<PermissionsRequest>> violations = validate(original);

    assertThat(violations.size(), equalTo(1));
    assertThat(violations, contains(hasViolationWithMessage("error.permission.missing_aces")));
  }

  @Test
  public void validation_ensuresOperationsIsNotEmpty() {
    PermissionsRequest original = new PermissionsRequest("foo", newArrayList());
    Set<ConstraintViolation<PermissionsRequest>> violations = validate(original);

    assertThat(violations.size(), equalTo(1));
    assertThat(violations, contains(hasViolationWithMessage("error.permission.missing_aces")));
  }
}
