package auth.back.server.config;

import org.junit.jupiter.api.Test;
import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.core.env.PropertySource;
import org.springframework.core.io.ClassPathResource;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;

class ProductionAuthConfigurationTest {

    @Test
    void productionProfile_requiresPublicIssuerAndFrontendUrls() throws IOException {
        PropertySource<?> properties = new YamlPropertySourceLoader()
                .load("production", new ClassPathResource("application-prod.yml"))
                .get(0);

        assertThat(properties.getProperty("app.security.issuer")).isEqualTo("${AUTH_ISSUER}");
        assertThat(properties.getProperty("app.oauth2.social.redirect-uris.muse"))
                .isEqualTo("${MUSE_FRONT_BASE_URL}/auth/callback");
        assertThat(properties.getProperty("app.oauth2.social.redirect-uris.zeroq-service"))
                .isEqualTo("${ZEROQ_FRONT_BASE_URL}/auth/callback");
        assertThat(properties.getProperty("app.oauth2.social.redirect-uris.zeroq-admin"))
                .isEqualTo("${ZEROQ_ADMIN_BASE_URL}/auth/callback");
        assertThat(properties.getProperty("app.oauth2.social.redirect-uris.semo"))
                .isEqualTo("${SEMO_FRONT_BASE_URL}/auth/callback");
        assertThat(properties.getProperty("app.oauth2.social.redirect-uris.stock"))
                .isEqualTo("${STOCK_FRONT_BASE_URL}/auth/callback");
        assertThat(properties.getProperty("app.cors.allowed-origins"))
                .isEqualTo("${AUTH_CORS_ALLOWED_ORIGINS}");
    }

    @Test
    void baseProfile_keepsRefreshTokenLifetimeAtFiveHours() throws IOException {
        PropertySource<?> properties = new YamlPropertySourceLoader()
                .load("base", new ClassPathResource("application.yml"))
                .get(0);

        assertThat(properties.getProperty("app.jwt.refresh-token-expiration-ms"))
                .isEqualTo(18_000_000);
    }
}
