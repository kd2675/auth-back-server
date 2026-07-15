package auth.back.server.service;

import auth.back.server.database.pub.entity.RefreshToken;
import auth.back.server.database.pub.entity.RefreshTokenStatus;
import auth.back.server.database.pub.entity.User;
import auth.back.server.database.pub.repository.RefreshTokenRepository;
import auth.common.core.exception.AuthException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.LocalDateTime;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class RefreshTokenServiceTest {

    private final RefreshTokenRepository repository = mock(RefreshTokenRepository.class);
    private final RefreshTokenService service = new RefreshTokenService(repository);
    private final User user = User.builder().userKey("user-key").username("user").build();

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(service, "refreshTokenExpirationMs", 18_000_000L);
        ReflectionTestUtils.setField(service, "refreshTokenReuseGraceMs", 5_000L);
        when(repository.save(any(RefreshToken.class))).thenAnswer(invocation -> invocation.getArgument(0));
    }

    @Test
    void createRefreshToken_secondDevice_keepsExistingSession() {
        RefreshToken created = service.createRefreshToken(user, "stock-front-service");

        assertThat(created.getStatus()).isEqualTo(RefreshTokenStatus.ACTIVE);
        assertThat(created.getClientId()).isEqualTo("stock-front-service");
        assertThat(created.getFamilyId()).isNotBlank();
        verify(repository).save(created);
    }

    @Test
    void rotate_activeToken_preservesAbsoluteExpiryAndRetiresOldToken() {
        LocalDateTime expiry = LocalDateTime.now().plusHours(5);
        RefreshToken current = activeToken(expiry);

        RefreshToken replacement = service.rotate(current);

        assertThat(current.getStatus()).isEqualTo(RefreshTokenStatus.ROTATED);
        assertThat(current.getReplacedByToken()).isEqualTo(replacement.getToken());
        assertThat(replacement.getFamilyId()).isEqualTo(current.getFamilyId());
        assertThat(replacement.getExpiryDate()).isEqualTo(expiry);
    }

    @Test
    void resolveForUse_rotatedTokenOutsideGrace_revokesActiveFamilyAsReplayDefense() {
        RefreshToken replayed = activeToken(LocalDateTime.now().plusHours(5));
        replayed.setStatus(RefreshTokenStatus.ROTATED);
        replayed.setRotatedAt(LocalDateTime.now().minusSeconds(10));
        replayed.setReplacedByToken("replacement-token");
        RefreshToken activeReplacement = activeToken(LocalDateTime.now().plusHours(5));
        when(repository.findByTokenForUpdate("replayed-token")).thenReturn(java.util.Optional.of(replayed));
        when(repository.findActiveByFamilyIdForUpdate("family-id")).thenReturn(List.of(activeReplacement));

        assertThatThrownBy(() -> service.resolveForUse("replayed-token"))
                .isInstanceOf(AuthException.class)
                .hasMessageContaining("reuse");
        assertThat(activeReplacement.getStatus()).isEqualTo(RefreshTokenStatus.REVOKED);
    }

    @Test
    void resolveForUse_rotatedTokenWithinGrace_reusesActiveReplacementForConcurrentTab() {
        RefreshToken rotated = activeToken(LocalDateTime.now().plusHours(5));
        rotated.setStatus(RefreshTokenStatus.ROTATED);
        rotated.setRotatedAt(LocalDateTime.now());
        rotated.setReplacedByToken("replacement-token");
        RefreshToken replacement = activeToken(LocalDateTime.now().plusHours(5));
        replacement.setToken("replacement-token");
        when(repository.findByTokenForUpdate("rotated-token")).thenReturn(java.util.Optional.of(rotated));
        when(repository.findByTokenForUpdate("replacement-token")).thenReturn(java.util.Optional.of(replacement));

        RefreshTokenUse use = service.resolveForUse("rotated-token");

        assertThat(use.concurrentRetry()).isTrue();
        assertThat(use.token()).isSameAs(replacement);
    }

    private RefreshToken activeToken(LocalDateTime expiry) {
        return RefreshToken.builder()
                .user(user)
                .clientId("stock-front-service")
                .familyId("family-id")
                .status(RefreshTokenStatus.ACTIVE)
                .token("refresh-" + System.nanoTime())
                .expiryDate(expiry)
                .build();
    }
}
