package auth.back.server.config;

import auth.back.server.database.pub.entity.User;
import lombok.extern.slf4j.Slf4j;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.util.StringUtils;

import javax.sql.DataSource;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

@Configuration
@RequiredArgsConstructor
@Slf4j
public class AuthorizationServerConfig {

    @Value("${app.security.issuer}")
    private String issuer;

    @Value("${app.oauth2.registered-client.zeroq-front-service.client-id:zeroq-front-service-web}")
    private String zeroqFrontServiceClientId;

    @Value("${app.oauth2.registered-client.zeroq-front-service.redirect-uri:http://localhost:3003/login}")
    private String zeroqFrontServiceRedirectUri;

    @Value("${app.oauth2.registered-client.zeroq-front-service.post-logout-redirect-uri:http://localhost:3003}")
    private String zeroqFrontServicePostLogoutRedirectUri;

    @Value("${app.oauth2.registered-client.zeroq-front-admin.client-id:zeroq-front-admin-web}")
    private String zeroqFrontAdminClientId;

    @Value("${app.oauth2.registered-client.zeroq-front-admin.redirect-uri:http://localhost:3002/login}")
    private String zeroqFrontAdminRedirectUri;

    @Value("${app.oauth2.registered-client.zeroq-front-admin.post-logout-redirect-uri:http://localhost:3002}")
    private String zeroqFrontAdminPostLogoutRedirectUri;

    @Value("${app.oauth2.registered-client.muse-front-service.client-id:muse-front-service-web}")
    private String museFrontServiceClientId;

    @Value("${app.oauth2.registered-client.muse-front-service.redirect-uri:http://localhost:3001/login}")
    private String museFrontServiceRedirectUri;

    @Value("${app.oauth2.registered-client.muse-front-service.post-logout-redirect-uri:http://localhost:3001}")
    private String museFrontServicePostLogoutRedirectUri;

    @Value("${app.oauth2.registered-client.semo-front-service.client-id:semo-front-service-web}")
    private String semoFrontServiceClientId;

    @Value("${app.oauth2.registered-client.semo-front-service.redirect-uri:http://localhost:3000/login}")
    private String semoFrontServiceRedirectUri;

    @Value("${app.oauth2.registered-client.semo-front-service.post-logout-redirect-uri:http://localhost:3000}")
    private String semoFrontServicePostLogoutRedirectUri;

    @Value("${app.jwt.access-token-expiration-ms:3600000}")
    private long accessTokenExpirationMs;

    @Value("${app.jwt.refresh-token-expiration-ms:1209600000}")
    private long refreshTokenExpirationMs;

    @Value("${app.oauth2.default-provider:naver}")
    private String defaultOAuthProvider;

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer();

        http
                .securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
                .with(authorizationServerConfigurer, authorizationServer ->
                        authorizationServer.oidc(Customizer.withDefaults())
                )
                .authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated());

        http.exceptionHandling(exceptions -> exceptions.authenticationEntryPoint((request, response, exception) -> {
            String provider = request.getParameter("provider");
            String normalizedProvider = normalizeProvider(provider);
            response.sendRedirect("/oauth2/authorization/" + normalizedProvider);
        }));

        return http.build();
    }

    private String normalizeProvider(String provider) {
        String value = StringUtils.hasText(provider) ? provider.trim().toLowerCase() : defaultOAuthProvider;
        if (!StringUtils.hasText(value) || !value.matches("^[a-z0-9-]+$")) {
            return "naver";
        }
        return value;
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
                .issuer(issuer)
                .build();
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        RSAKey rsaKey = Jwks.generateRsa();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return (selector, context) -> selector.select(jwkSet);
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository(DataSource dataSource) {
        return new JdbcRegisteredClientRepository(new JdbcTemplate(dataSource));
    }

    @Bean
    public OAuth2AuthorizationService authorizationService(
            DataSource dataSource,
            RegisteredClientRepository registeredClientRepository
    ) {
        return new org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService(
                new JdbcTemplate(dataSource), registeredClientRepository);
    }

    @Bean
    public OAuth2AuthorizationConsentService authorizationConsentService(
            DataSource dataSource,
            RegisteredClientRepository registeredClientRepository
    ) {
        return new org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService(
                new JdbcTemplate(dataSource), registeredClientRepository);
    }

    @Bean
    public CommandLineRunner registerWebClient(RegisteredClientRepository registeredClientRepository) {
        return args -> {
            TokenSettings tokenSettings = TokenSettings.builder()
                    .accessTokenTimeToLive(Duration.ofMillis(accessTokenExpirationMs))
                    .refreshTokenTimeToLive(Duration.ofMillis(refreshTokenExpirationMs))
                    .build();

            ClientSettings clientSettings = ClientSettings.builder()
                    .requireProofKey(true)
                    .requireAuthorizationConsent(false)
                    .build();

            List<ClientRegistrationConfig> registrations = List.of(
                    new ClientRegistrationConfig(zeroqFrontServiceClientId, zeroqFrontServiceRedirectUri, zeroqFrontServicePostLogoutRedirectUri),
                    new ClientRegistrationConfig(zeroqFrontAdminClientId, zeroqFrontAdminRedirectUri, zeroqFrontAdminPostLogoutRedirectUri),
                    new ClientRegistrationConfig(museFrontServiceClientId, museFrontServiceRedirectUri, museFrontServicePostLogoutRedirectUri),
                    new ClientRegistrationConfig(semoFrontServiceClientId, semoFrontServiceRedirectUri, semoFrontServicePostLogoutRedirectUri)
            );

            registrations.forEach(config ->
                    upsertRegisteredClient(
                            registeredClientRepository,
                            config,
                            tokenSettings,
                            clientSettings
                    )
            );
        };
    }

    @Bean
    public CommandLineRunner ensureAuthorizationSchemaColumns(JdbcTemplate jdbcTemplate) {
        return args -> {
            Map<String, String> missingColumnDdls = new LinkedHashMap<>();
            missingColumnDdls.put("user_code_value", "ALTER TABLE oauth2_authorization ADD COLUMN user_code_value BLOB NULL");
            missingColumnDdls.put("user_code_issued_at", "ALTER TABLE oauth2_authorization ADD COLUMN user_code_issued_at TIMESTAMP NULL");
            missingColumnDdls.put("user_code_expires_at", "ALTER TABLE oauth2_authorization ADD COLUMN user_code_expires_at TIMESTAMP NULL");
            missingColumnDdls.put("user_code_metadata", "ALTER TABLE oauth2_authorization ADD COLUMN user_code_metadata BLOB NULL");
            missingColumnDdls.put("device_code_value", "ALTER TABLE oauth2_authorization ADD COLUMN device_code_value BLOB NULL");
            missingColumnDdls.put("device_code_issued_at", "ALTER TABLE oauth2_authorization ADD COLUMN device_code_issued_at TIMESTAMP NULL");
            missingColumnDdls.put("device_code_expires_at", "ALTER TABLE oauth2_authorization ADD COLUMN device_code_expires_at TIMESTAMP NULL");
            missingColumnDdls.put("device_code_metadata", "ALTER TABLE oauth2_authorization ADD COLUMN device_code_metadata BLOB NULL");

            for (Map.Entry<String, String> entry : missingColumnDdls.entrySet()) {
                if (columnExists(jdbcTemplate, "oauth2_authorization", entry.getKey())) {
                    continue;
                }
                log.warn("Missing column detected: oauth2_authorization.{} - applying compatibility DDL", entry.getKey());
                jdbcTemplate.execute(entry.getValue());
            }

            // Cleanup legacy records serialized with custom principal class
            // that is no longer used in OAuth authorization attributes.
            int deleted = jdbcTemplate.update(
                    "DELETE FROM oauth2_authorization WHERE CONVERT(attributes USING utf8mb4) LIKE ?",
                    "%auth.back.server.service.oauth2.UserPrincipal%"
            );
            if (deleted > 0) {
                log.warn("Removed {} legacy oauth2_authorization rows containing deprecated UserPrincipal serialization", deleted);
            }

            int deletedLongTyped = jdbcTemplate.update(
                    "DELETE FROM oauth2_authorization WHERE CONVERT(attributes USING utf8mb4) LIKE ?",
                    "%java.lang.Long%"
            );
            if (deletedLongTyped > 0) {
                log.warn("Removed {} legacy oauth2_authorization rows containing typed java.lang.Long attributes", deletedLongTyped);
            }
        };
    }

    private boolean columnExists(JdbcTemplate jdbcTemplate, String tableName, String columnName) {
        Integer count = jdbcTemplate.queryForObject(
                """
                        SELECT COUNT(*)
                          FROM information_schema.columns
                         WHERE table_schema = DATABASE()
                           AND table_name = ?
                           AND column_name = ?
                        """,
                Integer.class,
                tableName,
                columnName
        );
        return count != null && count > 0;
    }

    private void upsertRegisteredClient(
            RegisteredClientRepository registeredClientRepository,
            ClientRegistrationConfig config,
            TokenSettings tokenSettings,
            ClientSettings clientSettings
    ) {
        if (!StringUtils.hasText(config.clientId()) || !StringUtils.hasText(config.redirectUri())) {
            return;
        }

        RegisteredClient existing = registeredClientRepository.findByClientId(config.clientId());
        String registeredClientId = existing != null ? existing.getId() : UUID.randomUUID().toString();

        RegisteredClient.Builder builder = RegisteredClient.withId(registeredClientId)
                .clientId(config.clientId())
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri(config.redirectUri())
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .scope("api")
                .tokenSettings(tokenSettings)
                .clientSettings(clientSettings);

        if (StringUtils.hasText(config.postLogoutRedirectUri())) {
            builder.postLogoutRedirectUri(config.postLogoutRedirectUri());
        }

        registeredClientRepository.save(builder.build());
    }

    private record ClientRegistrationConfig(
            String clientId,
            String redirectUri,
            String postLogoutRedirectUri
    ) {
    }

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer() {
        return context -> {
            if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
                Object principal = context.getPrincipal().getPrincipal();
                if (principal instanceof User user) {
                    context.getClaims().claim("userId", user.getId());
                    context.getClaims().claim("role", user.getRole());
                } else if (principal instanceof OAuth2AuthenticatedPrincipal oauthPrincipal) {
                    Object userId = oauthPrincipal.getAttributes().get("userId");
                    Object role = oauthPrincipal.getAttributes().get("role");
                    if (userId != null) {
                        context.getClaims().claim("userId", userId);
                    }
                    if (role != null) {
                        context.getClaims().claim("role", String.valueOf(role));
                    }
                }
            }
        };
    }
}
