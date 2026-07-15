package auth.back.server.service;

import auth.back.server.database.pub.entity.RefreshToken;
import auth.back.server.database.pub.entity.RefreshTokenStatus;
import auth.back.server.database.pub.entity.User;
import auth.back.server.database.pub.repository.RefreshTokenRepository;
import auth.common.core.exception.AuthException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Transactional
@Slf4j
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;

    @Value("${app.jwt.refresh-token-expiration-ms}")
    private long refreshTokenExpirationMs;

    @Value("${app.auth.refresh-token-reuse-grace-ms:5000}")
    private long refreshTokenReuseGraceMs;

    /**
     * Refresh Token 생성 및 저장
     */
    public RefreshToken createRefreshToken(User user, String clientId) {
        RefreshToken refreshToken = RefreshToken.builder()
                .user(user)
                .clientId(clientId)
                .familyId(UUID.randomUUID().toString())
                .status(RefreshTokenStatus.ACTIVE)
                .token(UUID.randomUUID().toString())
                .expiryDate(LocalDateTime.now().plus(Duration.ofMillis(refreshTokenExpirationMs)))
                .build();

        return refreshTokenRepository.save(refreshToken);
    }

    /**
     * Refresh Token 유효성 검증
     */
    public RefreshTokenUse resolveForUse(String tokenValue) {
        RefreshToken token = refreshTokenRepository.findByTokenForUpdate(tokenValue)
                .orElseThrow(() -> new AuthException("Refresh token not found"));

        if (token.getStatus() == RefreshTokenStatus.ROTATED && isWithinConcurrentRetryGrace(token)) {
            RefreshToken replacement = refreshTokenRepository.findByTokenForUpdate(token.getReplacedByToken())
                    .orElseThrow(() -> new AuthException("Refresh token replacement not found"));
            verifyActiveAndNotExpired(replacement);
            return new RefreshTokenUse(replacement, true);
        }

        verifyActiveAndNotExpired(token);
        return new RefreshTokenUse(token, false);
    }

    private void verifyActiveAndNotExpired(RefreshToken token) {
        if (token.getStatus() != RefreshTokenStatus.ACTIVE) {
            revokeActiveFamily(token.getFamilyId());
            throw new AuthException("Refresh token reuse detected");
        }
        if (token.getExpiryDate().isBefore(LocalDateTime.now())) {
            token.setStatus(RefreshTokenStatus.REVOKED);
            token.setRevokedAt(LocalDateTime.now());
            refreshTokenRepository.save(token);
            throw new AuthException("Refresh token has expired");
        }
    }

    /**
     * 토큰으로 Refresh Token 조회
     */
    private boolean isWithinConcurrentRetryGrace(RefreshToken token) {
        if (token.getRotatedAt() == null || token.getReplacedByToken() == null) {
            return false;
        }
        return !token.getRotatedAt()
                .plus(Duration.ofMillis(refreshTokenReuseGraceMs))
                .isBefore(LocalDateTime.now());
    }

    public RefreshToken rotate(RefreshToken currentToken) {
        verifyActiveAndNotExpired(currentToken);
        LocalDateTime now = LocalDateTime.now();
        RefreshToken replacement = RefreshToken.builder()
                .user(currentToken.getUser())
                .clientId(currentToken.getClientId())
                .familyId(currentToken.getFamilyId())
                .status(RefreshTokenStatus.ACTIVE)
                .token(UUID.randomUUID().toString())
                .expiryDate(currentToken.getExpiryDate())
                .build();
        refreshTokenRepository.save(replacement);

        currentToken.setStatus(RefreshTokenStatus.ROTATED);
        currentToken.setRotatedAt(now);
        currentToken.setReplacedByToken(replacement.getToken());
        refreshTokenRepository.save(currentToken);
        return replacement;
    }

    public void revokeByToken(String tokenValue) {
        refreshTokenRepository.findByTokenForUpdate(tokenValue).ifPresent(token -> {
            if (token.getStatus() == RefreshTokenStatus.ACTIVE) {
                token.setStatus(RefreshTokenStatus.REVOKED);
                token.setRevokedAt(LocalDateTime.now());
                refreshTokenRepository.save(token);
            }
        });
    }

    private void revokeActiveFamily(String familyId) {
        LocalDateTime now = LocalDateTime.now();
        for (RefreshToken activeToken : refreshTokenRepository.findActiveByFamilyIdForUpdate(familyId)) {
            activeToken.setStatus(RefreshTokenStatus.REVOKED);
            activeToken.setRevokedAt(now);
            refreshTokenRepository.save(activeToken);
        }
    }

}
