package auth.back.server.service;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import auth.back.server.database.pub.entity.RefreshToken;
import auth.back.server.database.pub.entity.RefreshTokenStatus;
import auth.back.server.database.pub.entity.User;
import auth.back.server.database.pub.repository.RefreshTokenRepository;
import auth.common.core.exception.AuthException;

@Service
@RequiredArgsConstructor
@Transactional(noRollbackFor = AuthException.class)
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
     * token 행을 잠근 뒤 ACTIVE·만료를 검증한다.
     * 회전 직후의 제한된 동시 요청만 replacement token으로 수렴시키고 그 밖의 재사용은 family를 폐기한다.
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

    /** 회전 시각과 replacement가 모두 있고 설정된 동시 재시도 grace 안인지 확인한다. */
    private boolean isWithinConcurrentRetryGrace(RefreshToken token) {
        if (token.getRotatedAt() == null || token.getReplacedByToken() == null) {
            return false;
        }
        return !token.getRotatedAt()
                .plus(Duration.ofMillis(refreshTokenReuseGraceMs))
                .isBefore(LocalDateTime.now());
    }

    /** 만료 시각과 familyId를 유지한 새 토큰을 만들고 기존 토큰을 ROTATED로 연결한다. */
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

    /** 로그아웃 시 아직 ACTIVE인 refresh token만 명시적으로 폐기한다. */
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
