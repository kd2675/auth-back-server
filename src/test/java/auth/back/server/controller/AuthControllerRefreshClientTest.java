package auth.back.server.controller;

import auth.back.server.database.pub.entity.AuthAuthorization;
import auth.back.server.database.pub.entity.AuthRegisteredClient;
import auth.back.server.database.pub.entity.RefreshToken;
import auth.back.server.database.pub.entity.User;
import auth.back.server.service.AuthAuthorizationService;
import auth.back.server.service.AuthRegisteredClientService;
import auth.back.server.service.JwtTokenProvider;
import auth.back.server.service.RefreshTokenService;
import auth.back.server.service.oauth2.OAuth2ClientAuthorizationService;
import auth.back.server.service.oauth2.OAuth2AuthorizationRevocationService;
import auth.common.core.dto.LoginRequest;
import auth.common.core.exception.AuthException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthControllerRefreshClientTest {

    @Mock
    private AuthenticationManager authenticationManager;

    @Mock
    private AuthAuthorizationService authAuthorizationService;

    @Mock
    private AuthRegisteredClientService authRegisteredClientService;

    @Mock
    private JwtTokenProvider jwtTokenProvider;

    @Mock
    private RefreshTokenService refreshTokenService;

    @Mock
    private OAuth2ClientAuthorizationService oAuth2ClientAuthorizationService;

    @Mock
    private OAuth2AuthorizationRevocationService oAuth2AuthorizationRevocationService;

    private AuthController authController;
    private MockHttpServletResponse response;

    @BeforeEach
    void setUp() {
        authController = new AuthController(
                authenticationManager,
                authAuthorizationService,
                authRegisteredClientService,
                jwtTokenProvider,
                refreshTokenService,
                oAuth2ClientAuthorizationService,
                oAuth2AuthorizationRevocationService
        );
        ReflectionTestUtils.setField(authController, "accessTokenExpirationMs", 3_600_000L);
        ReflectionTestUtils.setField(authController, "refreshTokenExpirationMs", 1_209_600_000L);
        response = new MockHttpServletResponse();
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(new MockHttpServletRequest(), response));
    }

    @AfterEach
    void tearDown() {
        RequestContextHolder.resetRequestAttributes();
    }

    @Test
    void login_stockClientHeader_issuesAccessTokenAndHttpOnlyRefreshCookie() {
        User user = User.builder()
                .username("stock-user")
                .userKey("stock-user-key")
                .role("USER")
                .build();
        Authentication authentication = org.mockito.Mockito.mock(Authentication.class);
        RefreshToken refreshToken = RefreshToken.builder()
                .token("refresh-token")
                .user(user)
                .expiryDate(LocalDateTime.now().plusDays(14))
                .build();
        when(authRegisteredClientService.validateActiveClient("stock-front-service"))
                .thenReturn(client("stock-front-service"));
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenReturn(authentication);
        when(authentication.getPrincipal()).thenReturn(user);
        when(jwtTokenProvider.generateAccessToken(
                "stock-user",
                "stock-user-key",
                "USER",
                "local",
                "stock-front-service"
        )).thenReturn("access-token");
        when(refreshTokenService.createRefreshToken(user)).thenReturn(refreshToken);

        var body = authController.login(
                "stock-front-service",
                new LoginRequest("stock-user", "password")
        );

        assertThat(body.getData().getAccessToken()).isEqualTo("access-token");
        assertThat(body.getData().getTokenType()).isEqualTo("Bearer");
        assertThat(body.getData().getExpiresIn()).isEqualTo(TimeUnit.MILLISECONDS.toSeconds(3_600_000L));
        assertThat(response.getCookie("refreshToken")).isNotNull();
        assertThat(response.getCookie("refreshToken").getValue()).isEqualTo("refresh-token");
        assertThat(response.getCookie("refreshToken").isHttpOnly()).isTrue();
        assertThat(response.getCookie("refreshToken").getMaxAge())
                .isEqualTo((int) Duration.ofMillis(1_209_600_000L).toSeconds());
        verify(authAuthorizationService).saveLoginAuthorization(
                org.mockito.Mockito.argThat(client -> "stock-front-service".equals(client.getClientId())),
                org.mockito.Mockito.eq(user),
                org.mockito.Mockito.eq("access-token"),
                org.mockito.Mockito.any(LocalDateTime.class),
                org.mockito.Mockito.any(LocalDateTime.class),
                org.mockito.Mockito.eq("refresh-token"),
                org.mockito.Mockito.any(LocalDateTime.class),
                org.mockito.Mockito.eq(refreshToken.getExpiryDate())
        );
    }

    @Test
    void refreshToken_matchingClientHeader_refreshesLocalToken() {
        AuthAuthorization authorization = authorization();
        RefreshToken refreshToken = refreshToken();
        when(authAuthorizationService.findByRefreshToken("refresh-token")).thenReturn(Optional.of(authorization));
        when(refreshTokenService.findByToken("refresh-token")).thenReturn(Optional.of(refreshToken));
        when(refreshTokenService.verifyExpiration(refreshToken)).thenReturn(refreshToken);
        when(authAuthorizationService.resolveClientId(authorization)).thenReturn("stock-front-service");
        when(authRegisteredClientService.validateActiveClient("stock-front-service"))
                .thenReturn(client("stock-front-service"));
        when(jwtTokenProvider.generateAccessToken(
                "stock-user",
                "stock-user-key",
                "USER",
                "local",
                "stock-front-service"
        )).thenReturn("new-access-token");

        var response = authController.refreshToken("stock-front-service", "refresh-token");

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().getData().getAccessToken()).isEqualTo("new-access-token");
        verify(authAuthorizationService).updateAccessToken(
                org.mockito.Mockito.eq(authorization),
                org.mockito.Mockito.eq("new-access-token"),
                org.mockito.Mockito.any(LocalDateTime.class),
                org.mockito.Mockito.any(LocalDateTime.class)
        );
    }

    @Test
    void refreshToken_mismatchedClientHeader_rejectsAndDoesNotIssueToken() {
        AuthAuthorization authorization = authorization();
        when(authAuthorizationService.findByRefreshToken("refresh-token")).thenReturn(Optional.of(authorization));
        when(refreshTokenService.findByToken("refresh-token")).thenReturn(Optional.of(refreshToken()));
        when(refreshTokenService.verifyExpiration(org.mockito.Mockito.any(RefreshToken.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));
        when(authAuthorizationService.resolveClientId(authorization)).thenReturn("semo-front-service");
        when(authRegisteredClientService.validateActiveClient("stock-front-service"))
                .thenReturn(client("stock-front-service"));

        var response = authController.refreshToken("stock-front-service", "refresh-token");

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);
        verify(jwtTokenProvider, never()).generateAccessToken(
                org.mockito.Mockito.anyString(),
                org.mockito.Mockito.anyString(),
                org.mockito.Mockito.anyString(),
                org.mockito.Mockito.anyString(),
                org.mockito.Mockito.anyString()
        );
        verify(authAuthorizationService, never()).updateAccessToken(
                org.mockito.Mockito.any(),
                org.mockito.Mockito.anyString(),
                org.mockito.Mockito.any(LocalDateTime.class),
                org.mockito.Mockito.any(LocalDateTime.class)
        );
    }

    @Test
    void refreshToken_withoutClientHeader_preservesLegacyRefreshBehavior() {
        AuthAuthorization authorization = authorization();
        RefreshToken refreshToken = refreshToken();
        when(authAuthorizationService.findByRefreshToken("refresh-token")).thenReturn(Optional.of(authorization));
        when(refreshTokenService.findByToken("refresh-token")).thenReturn(Optional.of(refreshToken));
        when(refreshTokenService.verifyExpiration(refreshToken)).thenReturn(refreshToken);
        when(authAuthorizationService.resolveClientId(authorization)).thenReturn("stock-front-service");
        when(jwtTokenProvider.generateAccessToken(
                "stock-user",
                "stock-user-key",
                "USER",
                "local",
                "stock-front-service"
        )).thenReturn("new-access-token");

        var response = authController.refreshToken(null, "refresh-token");

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().getData().getAccessToken()).isEqualTo("new-access-token");
        verify(authRegisteredClientService, never()).validateActiveClient(org.mockito.Mockito.anyString());
    }

    @Test
    void refreshToken_oauthMatchingClientHeader_refreshesWithOriginalSocialClientId() {
        RefreshToken refreshToken = refreshToken();
        when(authAuthorizationService.findByRefreshToken("oauth-refresh-token")).thenReturn(Optional.empty());
        when(oAuth2AuthorizationRevocationService.hasRefreshToken("oauth-refresh-token")).thenReturn(true);
        when(oAuth2AuthorizationRevocationService.isRefreshTokenInvalidated("oauth-refresh-token")).thenReturn(false);
        when(oAuth2AuthorizationRevocationService.isRefreshTokenExpired("oauth-refresh-token")).thenReturn(false);
        when(oAuth2AuthorizationRevocationService.findRefreshTokenRegisteredClientId("oauth-refresh-token"))
                .thenReturn(Optional.of("registered-stock-front-service"));
        when(oAuth2AuthorizationRevocationService.findRefreshTokenClientId("oauth-refresh-token"))
                .thenReturn(Optional.of("naver-stock"));
        when(refreshTokenService.findByToken("oauth-refresh-token")).thenReturn(Optional.of(refreshToken));
        when(refreshTokenService.verifyExpiration(refreshToken)).thenReturn(refreshToken);
        when(jwtTokenProvider.generateAccessToken(
                "stock-user",
                "stock-user-key",
                "USER",
                "oauth2",
                "naver-stock"
        )).thenReturn("oauth-access-token");

        var response = authController.refreshToken("stock-front-service", "oauth-refresh-token");

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().getData().getAccessToken()).isEqualTo("oauth-access-token");
        verify(oAuth2ClientAuthorizationService).validateRefreshClient(
                "stock-front-service",
                "registered-stock-front-service"
        );
    }

    @Test
    void refreshToken_oauthMismatchedClientHeader_rejectsAndDoesNotIssueToken() {
        when(authAuthorizationService.findByRefreshToken("oauth-refresh-token")).thenReturn(Optional.empty());
        when(oAuth2AuthorizationRevocationService.hasRefreshToken("oauth-refresh-token")).thenReturn(true);
        when(oAuth2AuthorizationRevocationService.isRefreshTokenInvalidated("oauth-refresh-token")).thenReturn(false);
        when(oAuth2AuthorizationRevocationService.isRefreshTokenExpired("oauth-refresh-token")).thenReturn(false);
        when(oAuth2AuthorizationRevocationService.findRefreshTokenRegisteredClientId("oauth-refresh-token"))
                .thenReturn(Optional.of("registered-semo-front-service"));
        org.mockito.Mockito.doThrow(new AuthException("Refresh token client mismatch"))
                .when(oAuth2ClientAuthorizationService)
                .validateRefreshClient("stock-front-service", "registered-semo-front-service");

        var response = authController.refreshToken("stock-front-service", "oauth-refresh-token");

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);
        verify(refreshTokenService, never()).findByToken("oauth-refresh-token");
        verify(jwtTokenProvider, never()).generateAccessToken(
                org.mockito.Mockito.anyString(),
                org.mockito.Mockito.anyString(),
                org.mockito.Mockito.anyString(),
                org.mockito.Mockito.anyString(),
                org.mockito.Mockito.any()
        );
    }

    private AuthAuthorization authorization() {
        return AuthAuthorization.builder()
                .id("authorization-id")
                .registeredClientId("registered-stock")
                .principalName("stock-user-key")
                .authorizationGrantType("password")
                .refreshTokenExpiresAt(LocalDateTime.now().plusHours(1))
                .invalidated(false)
                .build();
    }

    private RefreshToken refreshToken() {
        return RefreshToken.builder()
                .token("refresh-token")
                .user(User.builder()
                        .username("stock-user")
                        .userKey("stock-user-key")
                        .role("USER")
                        .build())
                .expiryDate(LocalDateTime.now().plusHours(1))
                .build();
    }

    private AuthRegisteredClient client(String clientId) {
        return AuthRegisteredClient.builder()
                .id("registered-" + clientId)
                .clientId(clientId)
                .enabled(true)
                .build();
    }
}
