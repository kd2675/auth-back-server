package auth.back.server.service;

import auth.back.server.database.pub.entity.AuthAuthorization;
import auth.back.server.database.pub.entity.AuthAuthorizationConsent;
import auth.back.server.database.pub.entity.AuthAuthorizationConsentId;
import auth.back.server.database.pub.entity.AuthRegisteredClient;
import auth.back.server.database.pub.entity.User;
import auth.back.server.database.pub.repository.AuthAuthorizationConsentRepository;
import auth.back.server.database.pub.repository.AuthAuthorizationRepository;
import auth.back.server.database.pub.repository.AuthRegisteredClientRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class AuthAuthorizationService {

    private final AuthAuthorizationRepository authAuthorizationRepository;
    private final AuthAuthorizationConsentRepository authAuthorizationConsentRepository;
    private final AuthRegisteredClientRepository authRegisteredClientRepository;

    @Transactional
    public void saveLoginAuthorization(
            AuthRegisteredClient registeredClient,
            User user,
            String accessTokenValue,
            LocalDateTime accessTokenIssuedAt,
            LocalDateTime accessTokenExpiresAt,
            String refreshTokenValue,
            LocalDateTime refreshTokenIssuedAt,
            LocalDateTime refreshTokenExpiresAt
    ) {
        saveConsent(registeredClient, user.getUserKey());
        invalidateActiveAuthorizations(user.getUserKey(), "replaced_by_new_login");

        List<String> scopes = parseScopes(registeredClient.getScopes());
        AuthAuthorization authorization = AuthAuthorization.builder()
                .id(UUID.randomUUID().toString())
                .registeredClientId(registeredClient.getId())
                .principalName(user.getUserKey())
                .authorizationGrantType("password")
                .authorizedScopes(String.join(",", scopes))
                .accessTokenHash(hashToken(accessTokenValue))
                .accessTokenValue(toBytes(accessTokenValue))
                .accessTokenIssuedAt(accessTokenIssuedAt)
                .accessTokenExpiresAt(accessTokenExpiresAt)
                .refreshTokenHash(hashToken(refreshTokenValue))
                .refreshTokenValue(toBytes(refreshTokenValue))
                .refreshTokenIssuedAt(refreshTokenIssuedAt)
                .refreshTokenExpiresAt(refreshTokenExpiresAt)
                .invalidated(false)
                .build();

        authAuthorizationRepository.save(authorization);
    }

    public Optional<AuthAuthorization> findByRefreshToken(String refreshTokenValue) {
        if (!StringUtils.hasText(refreshTokenValue)) {
            return Optional.empty();
        }
        return authAuthorizationRepository.findByRefreshTokenHash(hashToken(refreshTokenValue));
    }

    public Optional<AuthAuthorization> findByAccessToken(String accessTokenValue) {
        if (!StringUtils.hasText(accessTokenValue)) {
            return Optional.empty();
        }
        return authAuthorizationRepository.findByAccessTokenHash(hashToken(accessTokenValue));
    }

    public boolean isRefreshTokenInvalidated(String refreshTokenValue) {
        return findByRefreshToken(refreshTokenValue)
                .map(AuthAuthorization::getInvalidated)
                .orElse(false);
    }

    public boolean isRefreshTokenExpired(String refreshTokenValue) {
        return findByRefreshToken(refreshTokenValue)
                .map(authorization -> authorization.getRefreshTokenExpiresAt().isBefore(LocalDateTime.now()))
                .orElse(false);
    }

    @Transactional
    public void invalidateByAccessToken(String accessTokenValue) {
        findByAccessToken(accessTokenValue).ifPresent(authorization ->
                invalidateAuthorization(authorization, "logout_by_access_token")
        );
    }

    @Transactional
    public void invalidateByRefreshToken(String refreshTokenValue) {
        findByRefreshToken(refreshTokenValue).ifPresent(authorization ->
                invalidateAuthorization(authorization, "logout_by_refresh_token")
        );
    }

    @Transactional
    public void updateAccessToken(
            AuthAuthorization authorization,
            String newAccessTokenValue,
            LocalDateTime issuedAt,
            LocalDateTime expiresAt
    ) {
        authorization.setAccessTokenHash(hashToken(newAccessTokenValue));
        authorization.setAccessTokenValue(toBytes(newAccessTokenValue));
        authorization.setAccessTokenIssuedAt(issuedAt);
        authorization.setAccessTokenExpiresAt(expiresAt);
        authAuthorizationRepository.save(authorization);
    }

    public String resolveClientId(AuthAuthorization authorization) {
        return authRegisteredClientRepository.findById(authorization.getRegisteredClientId())
                .map(AuthRegisteredClient::getClientId)
                .orElse(authorization.getRegisteredClientId());
    }

    private void saveConsent(AuthRegisteredClient registeredClient, String userKey) {
        List<String> scopes = parseScopes(registeredClient.getScopes());
        String authorities = String.join(
                ",",
                scopes.stream().map(scope -> "SCOPE_" + scope).toList()
        );

        AuthAuthorizationConsent consent = AuthAuthorizationConsent.builder()
                .id(AuthAuthorizationConsentId.builder()
                        .registeredClientId(registeredClient.getId())
                        .principalName(userKey)
                        .build())
                .authorities(authorities)
                .build();

        authAuthorizationConsentRepository.save(consent);
    }

    private void invalidateActiveAuthorizations(String userKey, String reason) {
        List<AuthAuthorization> activeAuthorizations =
                authAuthorizationRepository.findByPrincipalNameAndInvalidatedFalse(userKey);

        for (AuthAuthorization activeAuthorization : activeAuthorizations) {
            invalidateAuthorization(activeAuthorization, reason);
        }
    }

    private void invalidateAuthorization(AuthAuthorization authorization, String reason) {
        authorization.setInvalidated(true);
        authorization.setInvalidatedAt(LocalDateTime.now());
        authorization.setInvalidationReason(reason);
        authAuthorizationRepository.save(authorization);
    }

    private List<String> parseScopes(String scopesRaw) {
        if (!StringUtils.hasText(scopesRaw)) {
            return List.of("api");
        }

        return Arrays.stream(scopesRaw.split(","))
                .map(String::trim)
                .filter(StringUtils::hasText)
                .distinct()
                .toList();
    }

    private byte[] toBytes(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }

    private String hashToken(String tokenValue) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(tokenValue.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 algorithm not available", e);
        }
    }
}
