package db.migration.common;

import io.pivotal.security.util.UuidUtil;
import org.flywaydb.core.api.migration.spring.SpringJdbcMigration;
import org.springframework.jdbc.core.JdbcTemplate;

import java.sql.Types;
import java.util.List;
import java.util.UUID;

import static io.pivotal.security.util.UuidUtil.makeUuid;

public class V44_2__migrate_encypted_values_to_encryped_value_table implements
    SpringJdbcMigration {

  public void migrate(JdbcTemplate jdbcTemplate) throws Exception {
    String databaseName = jdbcTemplate.getDataSource().getConnection().getMetaData()
        .getDatabaseProductName().toLowerCase();

    List<Object> credentialsWithEncryptedValues = jdbcTemplate.queryForList("select uuid from credential_version where encrypted_value is not null", Object.class);

    for (Object credentialUuid : credentialsWithEncryptedValues) {
      Object encryptedValueUuid = makeUuid(databaseName);
      jdbcTemplate.update(
          "insert into encrypted_value (" +
              "uuid, " +
              "encryption_key_uuid, " +
              "encrypted_value, " +
              "nonce, " +
              "updated_at" +
              ")" +
              "select "+
              "?, " +
              "encryption_key_uuid, " +
              "encrypted_value, " +
              "nonce, " +
              "updated_at "+
              "from credential_version " +
              "where uuid = ?",
          new Object[]{encryptedValueUuid, credentialUuid},
          new int[]{Types.VARBINARY, Types.VARBINARY});
      jdbcTemplate.update(
          "update credential_version " +
              "set encrypted_value_uuid = ? " +
              "where uuid = ?",
          new Object[]{encryptedValueUuid, credentialUuid},
          new int[]{Types.VARBINARY, Types.VARBINARY});
    }

    List<Object> passwordsWithEncryptedValues = jdbcTemplate.queryForList("select uuid from password_credential where encrypted_generation_parameters is not null", Object.class);

    for (Object passwordCredentialUuid : passwordsWithEncryptedValues) {
      Object encryptedValueUuid = makeUuid(databaseName);
      jdbcTemplate.update(
          "insert into encrypted_value (" +
              "uuid, " +
              "encryption_key_uuid, " +
              "encrypted_value, " +
              "nonce, " +
              "updated_at" +
              ")" +
              "select " +
              "?, " +
              "credential_version.encryption_key_uuid, " +
              "password_credential.encrypted_generation_parameters, "  +
              "password_credential.parameters_nonce, " +
              "credential_version.updated_at" +
              "from credential_version, password_credential " +
              "where credential_version.uuid=password_credential.uuid and " +
              "credential_version.uuid = ?);",
          new Object[]{encryptedValueUuid, passwordCredentialUuid},
          new int[]{Types.VARBINARY, Types.VARBINARY});
      jdbcTemplate.update(
          "update password_credential set password_parameters_uuid=? " +
              "where uuid = ?",
          encryptedValueUuid, passwordCredentialUuid);
    }


//    List<UUID> userCredentialsWithEncryptedValues = jdbcTemplate.queryForList("select uuid " +
//        "from user_credential where encrypted_generation_parameters is not null", UUID.class);
//
//    for (UUID record : userCredentialsWithEncryptedValues) {
//      Object uuid = makeUuid(databaseName);
//      jdbcTemplate.update(
//          "insert into encrypted_value values " +
//              "(select ?, credential_version.encryption_key_uuid, " +
//              "user_credential.encrypted_generation_parameters, "  +
//              "user_credential.parameters_nonce, credential_version.updated_at)" +
//              "from credential_version, user_credential " +
//              "where credential_version.uuid=user_credential.uuid and " +
//              "credential_version.uuid is ?);",
//          uuid, record);
//      jdbcTemplate.update(
//          "update user_credential set password_parameters_uuid=? " +
//              "where uuid = ?",
//          uuid, record);
//    }
  }

  private Object getUuidParam(String databaseName, UUID uuid) {
    if (databaseName.equals("postgresql")) {
      return uuid;
    } else {
      return UuidUtil.uuidToByteArray(uuid);
    }
  }
}
