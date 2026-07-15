package auth.back.server.service.oauth2;

import lombok.extern.slf4j.Slf4j;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.time.Instant;
import java.util.Optional;
import java.util.Set;

@Service
@RequiredArgsConstructor
@Slf4j
public class OAuth2AuthorizationRevocationService {

    private static final OAuth2TokenType REFRESH_TOKEN_TYPE = new OAuth2TokenType(OAuth2ParameterNames.REFRESH_TOKEN);

    private final OAuth2AuthorizationService authorizationService;

    @Transactional
    public void invalidateByAccessToken(String accessTokenValue) {
        invalidateByToken(accessTokenValue, OAuth2TokenType.ACCESS_TOKEN);
    }

    @Transactional
    public void invalidateByRefreshToken(String refreshTokenValue) {
        invalidateByToken(refreshTokenValue, REFRESH_TOKEN_TYPE);
    }

    public boolean isRefreshTokenInvalidated(String refreshTokenValue) {
        if (!StringUtils.hasText(refreshTokenValue)) {
            return false;
        }

        OAuth2Authorization authorization = findAuthorizationByToken(refreshTokenValue, REFRESH_TOKEN_TYPE);
        if (authorization == null || authorization.getRefreshToken() == null) {
            return false;
        }

        Object invalidated = authorization.getRefreshToken().getMetadata()
                .get(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME);
        return Boolean.TRUE.equals(invalidated);
    }

    public boolean hasRefreshToken(String refreshTokenValue) {
        if (!StringUtils.hasText(refreshTokenValue)) {
            return false;
        }

        OAuth2Authorization authorization = findAuthorizationByToken(refreshTokenValue, REFRESH_TOKEN_TYPE);
        return authorization != null && authorization.getRefreshToken() != null;
    }

    public boolean isRefreshTokenExpired(String refreshTokenValue) {
        if (!StringUtils.hasText(refreshTokenValue)) {
            return false;
        }

        OAuth2Authorization authorization = findAuthorizationByToken(refreshTokenValue, REFRESH_TOKEN_TYPE);
        if (authorization == null || authorization.getRefreshToken() == null) {
            return false;
        }

        Instant expiresAt = authorization.getRefreshToken().getToken().getExpiresAt();
        return expiresAt != null && expiresAt.isBefore(Instant.now());
    }

    public Optional<String> findRefreshTokenRegisteredClientId(String refreshTokenValue) {
        if (!StringUtils.hasText(refreshTokenValue)) {
            return Optional.empty();
        }

        OAuth2Authorization authorization = findAuthorizationByToken(refreshTokenValue, REFRESH_TOKEN_TYPE);
        if (authorization == null || authorization.getRefreshToken() == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(authorization.getRegisteredClientId())
                .filter(StringUtils::hasText);
    }

    public Optional<String> findRefreshTokenClientId(String refreshTokenValue) {
        if (!StringUtils.hasText(refreshTokenValue)) {
            return Optional.empty();
        }

        OAuth2Authorization authorization = findAuthorizationByToken(refreshTokenValue, REFRESH_TOKEN_TYPE);
        if (authorization == null || authorization.getRefreshToken() == null) {
            return Optional.empty();
        }
        Object clientId = authorization.getAttribute("client_id");
        if (clientId instanceof String clientIdValue && StringUtils.hasText(clientIdValue)) {
            return Optional.of(clientIdValue);
        }
        return Optional.empty();
    }

    @Transactional
    public void updateAccessToken(
            String refreshTokenValue,
            String newAccessTokenValue,
            Instant accessTokenIssuedAt,
            Instant accessTokenExpiresAt
    ) {
        OAuth2Authorization authorization = findAuthorizationByToken(refreshTokenValue, REFRESH_TOKEN_TYPE);
        if (authorization == null) {
            throw new IllegalStateException("OAuth2 authorization not found for access token update");
        }
        OAuth2AccessToken newAccessToken = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                newAccessTokenValue,
                accessTokenIssuedAt,
                accessTokenExpiresAt,
                authorization.getAuthorizedScopes()
        );
        authorizationService.save(OAuth2Authorization.from(authorization)
                .accessToken(newAccessToken)
                .build());
    }

    @Transactional
    public void rotateTokens(
            String currentRefreshTokenValue,
            String newAccessTokenValue,
            Instant accessTokenIssuedAt,
            Instant accessTokenExpiresAt,
            String newRefreshTokenValue,
            Instant refreshTokenIssuedAt,
            Instant refreshTokenExpiresAt
    ) {
        OAuth2Authorization authorization = findAuthorizationByToken(currentRefreshTokenValue, REFRESH_TOKEN_TYPE);
        if (authorization == null) {
            throw new IllegalStateException("OAuth2 authorization not found for refresh rotation");
        }
        Set<String> scopes = authorization.getAuthorizedScopes();
        OAuth2AccessToken newAccessToken = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                newAccessTokenValue,
                accessTokenIssuedAt,
                accessTokenExpiresAt,
                scopes
        );
        OAuth2RefreshToken newRefreshToken = new OAuth2RefreshToken(
                newRefreshTokenValue,
                refreshTokenIssuedAt,
                refreshTokenExpiresAt
        );
        authorizationService.save(OAuth2Authorization.from(authorization)
                .accessToken(newAccessToken)
                .refreshToken(newRefreshToken)
                .build());
    }

    private void invalidateByToken(String tokenValue, OAuth2TokenType tokenType) {
        if (!StringUtils.hasText(tokenValue)) {
            return;
        }

        OAuth2Authorization authorization = findAuthorizationByToken(tokenValue, tokenType);
        if (authorization == null) {
            return;
        }

        OAuth2Authorization.Builder builder = OAuth2Authorization.from(authorization);

        OAuth2Authorization.Token<?> accessToken = authorization.getAccessToken();
        if (accessToken != null) {
            builder.token(accessToken.getToken(), metadata ->
                    metadata.put(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, true)
            );
        }

        OAuth2Authorization.Token<?> refreshToken = authorization.getRefreshToken();
        if (refreshToken != null) {
            builder.token(refreshToken.getToken(), metadata ->
                    metadata.put(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, true)
            );
        }

        authorizationService.save(builder.build());
    }

    private OAuth2Authorization findAuthorizationByToken(String tokenValue, OAuth2TokenType tokenType) {
        try {
            return authorizationService.findByToken(tokenValue, tokenType);
        } catch (IllegalArgumentException ex) {
            log.warn("Failed to deserialize OAuth2Authorization by token. tokenType={}, reason={}", tokenType.getValue(), ex.getMessage());
            return null;
        }
    }
}
