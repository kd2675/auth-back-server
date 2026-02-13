package auth.back.server.config;

import auth.back.server.database.pub.entity.User;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
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

import javax.sql.DataSource;
import java.time.Duration;
import java.util.UUID;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

@Configuration
@RequiredArgsConstructor
public class AuthorizationServerConfig {

    @Value("${app.security.issuer}")
    private String issuer;

    @Value("${app.oauth2.client.web.client-id}")
    private String webClientId;

    @Value("${app.oauth2.client.web.redirect-uri}")
    private String webRedirectUri;

    @Value("${app.oauth2.client.web.post-logout-redirect-uri}")
    private String webPostLogoutRedirectUri;

    @Value("${app.jwt.access-token-expiration-ms:3600000}")
    private long accessTokenExpirationMs;

    @Value("${app.jwt.refresh-token-expiration-ms:1209600000}")
    private long refreshTokenExpirationMs;

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
            RegisteredClient existing = registeredClientRepository.findByClientId(webClientId);
            if (existing != null) {
                return;
            }

            TokenSettings tokenSettings = TokenSettings.builder()
                    .accessTokenTimeToLive(Duration.ofMillis(accessTokenExpirationMs))
                    .refreshTokenTimeToLive(Duration.ofMillis(refreshTokenExpirationMs))
                    .build();

            ClientSettings clientSettings = ClientSettings.builder()
                    .requireProofKey(true)
                    .requireAuthorizationConsent(false)
                    .build();

            RegisteredClient webClient = RegisteredClient.withId(UUID.randomUUID().toString())
                    .clientId(webClientId)
                    .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                    .redirectUri(webRedirectUri)
                    .postLogoutRedirectUri(webPostLogoutRedirectUri)
                    .scope(OidcScopes.OPENID)
                    .scope(OidcScopes.PROFILE)
                    .scope("api")
                    .tokenSettings(tokenSettings)
                    .clientSettings(clientSettings)
                    .build();

            registeredClientRepository.save(webClient);
        };
    }

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer() {
        return context -> {
            if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
                Object principal = context.getPrincipal().getPrincipal();
                if (principal instanceof User user) {
                    context.getClaims().claim("userId", user.getId());
                    context.getClaims().claim("role", user.getRole());
                }
            }
        };
    }
}
