package auth.back.server.service.oauth2;

import lombok.extern.slf4j.Slf4j;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.time.Instant;

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
