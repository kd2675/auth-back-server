package auth.back.server.service.oauth2;

import auth.back.server.database.pub.entity.User;
import auth.common.core.exception.AuthException;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class OAuth2ClientAuthorizationService {

    private final RegisteredClientRepository registeredClientRepository;
    private final OAuth2AuthorizationService authorizationService;
    private final OAuth2AuthorizationConsentService authorizationConsentService;

    @Value("${app.oauth2.front-clients.muse.client-id}")
    private String museClientId;

    @Value("${app.oauth2.front-clients.zeroq-service.client-id}")
    private String zeroqServiceClientId;

    @Value("${app.oauth2.front-clients.zeroq-admin.client-id}")
    private String zeroqAdminClientId;

    @Value("${app.oauth2.front-clients.semo.client-id}")
    private String semoClientId;

    @Transactional
    public void validateAndSaveAuthorization(
            String clientId,
            User user,
            String accessTokenValue,
            Instant accessTokenIssuedAt,
            Instant accessTokenExpiresAt,
            String refreshTokenValue,
            Instant refreshTokenIssuedAt,
            Instant refreshTokenExpiresAt
    ) {
        RegisteredClient registeredClient = resolveRegisteredClient(clientId);
        validateRegisteredClient(registeredClient, clientId);
        saveConsent(registeredClient, user);
        saveAuthorization(
                registeredClient,
                user,
                clientId,
                accessTokenValue,
                accessTokenIssuedAt,
                accessTokenExpiresAt,
                refreshTokenValue,
                refreshTokenIssuedAt,
                refreshTokenExpiresAt
        );
    }

    private RegisteredClient resolveRegisteredClient(String clientId) {
        String resolvedClientId = resolveClientId(clientId);
        RegisteredClient registeredClient = registeredClientRepository.findByClientId(resolvedClientId);
        if (registeredClient == null) {
            throw new AuthException("Registered client not found: " + resolvedClientId);
        }
        return registeredClient;
    }

    private void validateRegisteredClient(RegisteredClient registeredClient, String clientId) {
        Set<AuthorizationGrantType> grantTypes = registeredClient.getAuthorizationGrantTypes();
        if (!grantTypes.contains(AuthorizationGrantType.AUTHORIZATION_CODE)) {
            throw new AuthException("Client does not support authorization_code grant: " + clientId);
        }
        if (!grantTypes.contains(AuthorizationGrantType.REFRESH_TOKEN)) {
            throw new AuthException("Client does not support refresh_token grant: " + clientId);
        }
        if (registeredClient.getScopes() == null || registeredClient.getScopes().isEmpty()) {
            throw new AuthException("Client scopes are empty: " + clientId);
        }
    }

    private void saveConsent(RegisteredClient registeredClient, User user) {
        OAuth2AuthorizationConsent.Builder consentBuilder = OAuth2AuthorizationConsent
                .withId(registeredClient.getId(), user.getUserKey());
        for (String scope : registeredClient.getScopes()) {
            consentBuilder.authority(new SimpleGrantedAuthority("SCOPE_" + scope));
        }
        authorizationConsentService.save(consentBuilder.build());
    }

    private void saveAuthorization(
            RegisteredClient registeredClient,
            User user,
            String clientId,
            String accessTokenValue,
            Instant accessTokenIssuedAt,
            Instant accessTokenExpiresAt,
            String refreshTokenValue,
            Instant refreshTokenIssuedAt,
            Instant refreshTokenExpiresAt
    ) {
        OAuth2AccessToken accessToken = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                accessTokenValue,
                accessTokenIssuedAt,
                accessTokenExpiresAt,
                registeredClient.getScopes()
        );

        OAuth2RefreshToken refreshToken = new OAuth2RefreshToken(
                refreshTokenValue,
                refreshTokenIssuedAt,
                refreshTokenExpiresAt
        );

        OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(registeredClient)
                .id(UUID.randomUUID().toString())
                .principalName(user.getUserKey())
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizedScopes(registeredClient.getScopes())
                .attribute("client_id", clientId)
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();

        authorizationService.save(authorization);
    }

    private String resolveClientId(String clientId) {
        if (clientId == null) {
            throw new AuthException("Client id is required");
        }

        if (clientId.endsWith("-muse")) {
            return museClientId;
        }
        if (clientId.endsWith("-zeroq-service")) {
            return zeroqServiceClientId;
        }
        if (clientId.endsWith("-zeroq-admin")) {
            return zeroqAdminClientId;
        }
        if (clientId.endsWith("-semo")) {
            return semoClientId;
        }

        throw new AuthException("Unknown client id: " + clientId);
    }
}
