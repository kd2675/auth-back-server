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
import java.util.List;
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

    @Value("${app.oauth2.front-clients.muse.client-id}")
    private String museClientId;

    @Value("${app.oauth2.front-clients.muse.redirect-uri}")
    private String museRedirectUri;

    @Value("${app.oauth2.front-clients.muse.post-logout-redirect-uri}")
    private String musePostLogoutRedirectUri;

    @Value("${app.oauth2.front-clients.zeroq-service.client-id}")
    private String zeroqServiceClientId;

    @Value("${app.oauth2.front-clients.zeroq-service.redirect-uri}")
    private String zeroqServiceRedirectUri;

    @Value("${app.oauth2.front-clients.zeroq-service.post-logout-redirect-uri}")
    private String zeroqServicePostLogoutRedirectUri;

    @Value("${app.oauth2.front-clients.zeroq-admin.client-id}")
    private String zeroqAdminClientId;

    @Value("${app.oauth2.front-clients.zeroq-admin.redirect-uri}")
    private String zeroqAdminRedirectUri;

    @Value("${app.oauth2.front-clients.zeroq-admin.post-logout-redirect-uri}")
    private String zeroqAdminPostLogoutRedirectUri;

    @Value("${app.oauth2.front-clients.semo.client-id}")
    private String semoClientId;

    @Value("${app.oauth2.front-clients.semo.redirect-uri}")
    private String semoRedirectUri;

    @Value("${app.oauth2.front-clients.semo.post-logout-redirect-uri}")
    private String semoPostLogoutRedirectUri;

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
    public CommandLineRunner registerFrontClients(RegisteredClientRepository registeredClientRepository) {
        return args -> {
            TokenSettings tokenSettings = TokenSettings.builder()
                    .accessTokenTimeToLive(Duration.ofMillis(accessTokenExpirationMs))
                    .refreshTokenTimeToLive(Duration.ofMillis(refreshTokenExpirationMs))
                    .build();

            ClientSettings clientSettings = ClientSettings.builder()
                    .requireProofKey(true)
                    .requireAuthorizationConsent(false)
                    .build();

            for (FrontClientSpec spec : buildFrontClientSpecs()) {
                upsertFrontClient(registeredClientRepository, spec, tokenSettings, clientSettings);
            }
        };
    }

    private void upsertFrontClient(
            RegisteredClientRepository repository,
            FrontClientSpec spec,
            TokenSettings tokenSettings,
            ClientSettings clientSettings
    ) {
        RegisteredClient existing = repository.findByClientId(spec.clientId());
        RegisteredClient.Builder builder = existing == null
                ? RegisteredClient.withId(UUID.randomUUID().toString())
                : RegisteredClient.from(existing);

        RegisteredClient client = builder
                .clientId(spec.clientId())
                .clientName(spec.clientId())
                .clientAuthenticationMethods(methods -> {
                    methods.clear();
                    methods.add(ClientAuthenticationMethod.NONE);
                })
                .authorizationGrantTypes(grantTypes -> {
                    grantTypes.clear();
                    grantTypes.add(AuthorizationGrantType.AUTHORIZATION_CODE);
                    grantTypes.add(AuthorizationGrantType.REFRESH_TOKEN);
                })
                .redirectUris(redirectUris -> {
                    redirectUris.clear();
                    redirectUris.add(spec.redirectUri());
                })
                .postLogoutRedirectUris(postLogoutRedirectUris -> {
                    postLogoutRedirectUris.clear();
                    postLogoutRedirectUris.add(spec.postLogoutRedirectUri());
                })
                .scopes(scopes -> {
                    scopes.clear();
                    scopes.add(OidcScopes.OPENID);
                    scopes.add(OidcScopes.PROFILE);
                    scopes.add("api");
                })
                .tokenSettings(tokenSettings)
                .clientSettings(clientSettings)
                .build();

        repository.save(client);
    }

    private List<FrontClientSpec> buildFrontClientSpecs() {
        return List.of(
                new FrontClientSpec(museClientId, museRedirectUri, musePostLogoutRedirectUri),
                new FrontClientSpec(zeroqServiceClientId, zeroqServiceRedirectUri, zeroqServicePostLogoutRedirectUri),
                new FrontClientSpec(zeroqAdminClientId, zeroqAdminRedirectUri, zeroqAdminPostLogoutRedirectUri),
                new FrontClientSpec(semoClientId, semoRedirectUri, semoPostLogoutRedirectUri)
        );
    }

    private record FrontClientSpec(
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
                }
            }
        };
    }
}
