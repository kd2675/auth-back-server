package auth.back.server.config.handler;

import auth.back.server.database.pub.entity.RefreshToken;
import auth.back.server.database.pub.entity.User;
import auth.back.server.database.pub.repository.UserRepository;
import auth.common.core.exception.AuthException;
import auth.back.server.service.JwtTokenProvider;
import auth.back.server.service.RefreshTokenService;
import auth.back.server.service.oauth2.OAuth2LoginChannelService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;
import web.common.core.utils.CookieUtils;

import java.io.IOException;
import java.util.concurrent.TimeUnit;

@Component
@RequiredArgsConstructor
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final UserRepository userRepository;
    private final JwtTokenProvider jwtTokenProvider;
    private final RefreshTokenService refreshTokenService;
    private final OAuth2LoginChannelService oauth2LoginChannelService;

    @Value("${app.jwt.access-token-expiration-ms:3600000}")
    private long accessTokenExpirationMs;

    @Value("${app.jwt.refresh-token-expiration-ms:1209600000}")
    private long refreshTokenExpirationMs;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
            throws IOException {
        String targetUrl = determineTargetUrl(request, authentication);
        if (response.isCommitted()) {
            return;
        }
        clearAuthenticationAttributes(request);
        getRedirectStrategy().sendRedirect(request, response, targetUrl);
    }

    protected String determineTargetUrl(HttpServletRequest request, Authentication authentication) {
        OAuth2User oauthUser = (OAuth2User) authentication.getPrincipal();
        String userIdValue = oauthUser.getAttribute("userId");
        String email = oauthUser.getAttribute("email");
        String username = oauthUser.getAttribute("username");
        User user = resolveUser(userIdValue, email, username);

        String accessToken = jwtTokenProvider.generateAccessToken(
                user.getUsername(),
                user.getId(),
                user.getRole()
        );
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(user);

        int accessMaxAgeSeconds = (int) TimeUnit.MILLISECONDS.toSeconds(accessTokenExpirationMs);
        int refreshMaxAgeSeconds = (int) TimeUnit.MILLISECONDS.toSeconds(refreshTokenExpirationMs);
        CookieUtils.createCookie("accessToken", accessToken, accessMaxAgeSeconds);
        CookieUtils.createCookie("refreshToken", refreshToken.getToken(), refreshMaxAgeSeconds);

        String channel = oauth2LoginChannelService.resolveFromRequest(request);
        String redirectUri = oauth2LoginChannelService.resolveRedirectUri(channel);
        oauth2LoginChannelService.clearRememberedChannel();

        return UriComponentsBuilder.fromUriString(redirectUri)
                .queryParam("oauth", "1")
                .build()
                .toUriString();
    }

    private User resolveUser(String userIdValue, String email, String username) {
        if (userIdValue != null && !userIdValue.isBlank()) {
            try {
                long userId = Long.parseLong(userIdValue);
                return userRepository.findById(userId).orElseThrow();
            } catch (NumberFormatException ignored) {
                // fallback to email/username lookup
            }
        }
        if (email != null && !email.isBlank()) {
            return userRepository.findByEmail(email)
                    .orElseGet(() -> findByUsername(username));
        }
        return findByUsername(username);
    }

    private User findByUsername(String username) {
        if (username == null || username.isBlank()) {
            throw new AuthException("OAuth2 authenticated user cannot be resolved");
        }
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new AuthException("OAuth2 authenticated user cannot be resolved"));
    }
}
