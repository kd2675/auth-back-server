package auth.back.server.config.handler;

import auth.back.server.database.pub.entity.RefreshToken;
import auth.back.server.database.pub.entity.User;
import auth.back.server.service.JwtTokenProvider;
import auth.back.server.service.RefreshTokenCookieService;
import auth.back.server.service.RefreshTokenService;
import auth.back.server.service.oauth2.OAuth2ClientAuthorizationService;
import auth.back.server.service.oauth2.UserPrincipal;
import auth.common.core.constant.UserRole;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class OAuth2AuthenticationSuccessHandlerTest {

    private final JwtTokenProvider jwtTokenProvider = mock(JwtTokenProvider.class);
    private final RefreshTokenService refreshTokenService = mock(RefreshTokenService.class);
    private final OAuth2ClientAuthorizationService oAuth2ClientAuthorizationService = mock(OAuth2ClientAuthorizationService.class);
    private final OAuth2AuthenticationSuccessHandler handler = new OAuth2AuthenticationSuccessHandler(
            jwtTokenProvider,
            new RefreshTokenCookieService("refreshToken", "/auth", "Lax", false),
            refreshTokenService,
            oAuth2ClientAuthorizationService
    );

    @AfterEach
    void tearDown() {
        RequestContextHolder.resetRequestAttributes();
    }

    @Test
    void onAuthenticationSuccess_stockProvider_redirectsToStockCallbackWithoutFrontChannelToken() throws Exception {
        ReflectionTestUtils.setField(handler, "defaultRedirectUri", "http://localhost:3001/login");
        ReflectionTestUtils.setField(handler, "museRedirectUri", "http://localhost:3000/login");
        ReflectionTestUtils.setField(handler, "zeroqServiceRedirectUri", "http://localhost:3001/login");
        ReflectionTestUtils.setField(handler, "zeroqAdminRedirectUri", "http://localhost:3002/login");
        ReflectionTestUtils.setField(handler, "semoRedirectUri", "http://localhost:3003/login");
        ReflectionTestUtils.setField(handler, "stockRedirectUri", "http://localhost:3005/auth/callback");
        ReflectionTestUtils.setField(handler, "refreshTokenExpirationMs", 18_000_000L);
        ReflectionTestUtils.setField(handler, "accessTokenExpirationMs", 3_600_000L);
        User user = User.builder()
                .userKey("stock-user-key")
                .username("stock-user")
                .email("stock@example.com")
                .role(UserRole.USER)
                .build();
        when(jwtTokenProvider.generateAccessToken(user, "oauth2", "naver-stock")).thenReturn("access-token");
        when(refreshTokenService.createRefreshToken(user, "naver-stock")).thenReturn(RefreshToken.builder()
                .user(user)
                .token("refresh-token")
                .expiryDate(LocalDateTime.now().plusHours(5))
                .build());
        var principal = new UserPrincipal(user, Map.of());
        var authentication = new OAuth2AuthenticationToken(principal, principal.getAuthorities(), "naver-stock");
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/login/oauth2/code/naver-stock");
        MockHttpServletResponse response = new MockHttpServletResponse();
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request, response));

        handler.onAuthenticationSuccess(request, response, authentication);

        assertThat(response.getRedirectedUrl()).isEqualTo("http://localhost:3005/auth/callback");
        assertThat(response.getHeader("Set-Cookie"))
                .contains("refreshToken=refresh-token")
                .contains("Path=/auth")
                .contains("HttpOnly")
                .contains("SameSite=Lax");
        verify(oAuth2ClientAuthorizationService).validateAndSaveAuthorization(
                eq("naver-stock"),
                eq(user),
                eq("access-token"),
                any(Instant.class),
                any(Instant.class),
                eq("refresh-token"),
                any(Instant.class),
                any(Instant.class)
        );
    }
}
