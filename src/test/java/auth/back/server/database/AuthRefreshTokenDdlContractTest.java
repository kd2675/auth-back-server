package auth.back.server.database;

import org.junit.jupiter.api.Test;
import org.springframework.core.io.ClassPathResource;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;

class AuthRefreshTokenDdlContractTest {

    @Test
    void authAll_refreshTokenSchema_supportsMultipleSessionsAndRotation() throws IOException {
        String ddl = new ClassPathResource("db/ddl/auth_all.sql")
                .getContentAsString(StandardCharsets.UTF_8);

        assertThat(ddl)
                .contains("family_id VARCHAR(36) NOT NULL")
                .contains("status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE'")
                .contains("refresh_token_ttl_seconds INT NOT NULL DEFAULT 18000")
                .contains("idx_refresh_tokens_family_status")
                .doesNotContain("uk_refresh_tokens_user_key UNIQUE");
    }

    @Test
    void refreshTokenRotationAlter_backfillsBeforeMakingColumnsRequired() throws IOException {
        String ddl = new ClassPathResource("db/ddl/auth_refresh_token_rotation_alter.sql")
                .getContentAsString(StandardCharsets.UTF_8);

        assertThat(ddl.indexOf("UPDATE refresh_tokens"))
                .isLessThan(ddl.indexOf("MODIFY COLUMN client_id"));
    }
}
