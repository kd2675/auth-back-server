package auth.back.server.config.handler;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import auth.back.server.database.pub.entity.RefreshToken;
import auth.back.server.database.pub.entity.User;
import auth.back.server.service.JwtTokenProvider;
import auth.back.server.service.RefreshTokenCookieService;
import auth.back.server.service.RefreshTokenService;
import auth.back.server.service.oauth2.OAuth2ClientAuthorizationService;
import auth.back.server.service.oauth2.UserPrincipal;

@Component
@RequiredArgsConstructor
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final JwtTokenProvider jwtTokenProvider;
    private final RefreshTokenCookieService refreshTokenCookieService;
    private final RefreshTokenService refreshTokenService;
    private final OAuth2ClientAuthorizationService oAuth2ClientAuthorizationService;

    @Value("${app.oauth2.social.default-redirect-uri}")
    private String defaultRedirectUri;

    @Value("${app.oauth2.social.redirect-uris.muse}")
    private String museRedirectUri;

    @Value("${app.oauth2.social.redirect-uris.zeroq-service}")
    private String zeroqServiceRedirectUri;

    @Value("${app.oauth2.social.redirect-uris.zeroq-admin}")
    private String zeroqAdminRedirectUri;

    @Value("${app.oauth2.social.redirect-uris.semo}")
    private String semoRedirectUri;

    @Value("${app.oauth2.social.redirect-uris.stock}")
    private String stockRedirectUri;

    @Value("${app.jwt.refresh-token-expiration-ms}")
    private long refreshTokenExpirationMs;

    @Value("${app.jwt.access-token-expiration-ms}")
    private long accessTokenExpirationMs;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        String targetUrl = determineTargetUrl(request, response, authentication);

        if (response.isCommitted()) {
            logger.debug("Response has already been committed. Unable to redirect to " + targetUrl);
            return;
        }

        clearAuthenticationAttributes(request);
        getRedirectStrategy().sendRedirect(request, response, targetUrl);
    }

    protected String determineTargetUrl(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();
        User user = userPrincipal.getUser();
        String clientId = resolveClientId(authentication);

        String accessToken = jwtTokenProvider.generateAccessToken(user, "oauth2", clientId);
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(user, clientId);
        Instant now = Instant.now();
        Instant accessTokenExpiresAt = now.plusMillis(accessTokenExpirationMs);
        Instant refreshTokenExpiresAt = now.plusMillis(refreshTokenExpirationMs);

        oAuth2ClientAuthorizationService.validateAndSaveAuthorization(
                clientId,
                user,
                accessToken,
                now,
                accessTokenExpiresAt,
                refreshToken.getToken(),
                now,
                refreshTokenExpiresAt
        );

        refreshTokenCookieService.write(
                response,
                clientId,
                refreshToken.getToken(),
                Duration.ofMillis(refreshTokenExpirationMs)
        );

        // The access token must never travel through the browser URL. Every front client
        // completes the login by exchanging the HttpOnly refresh cookie on its callback page.
        return resolveFrontRedirectUri(clientId);
    }

    private String resolveClientId(Authentication authentication) {
        if (authentication instanceof OAuth2AuthenticationToken oauth2Token) {
            return oauth2Token.getAuthorizedClientRegistrationId();
        }
        return "";
    }

    private String resolveFrontRedirectUri(String clientId) {
        if (clientId == null) {
            return defaultRedirectUri;
        }

        if (clientId.endsWith("-muse")) {
            return museRedirectUri;
        }
        if (clientId.endsWith("-zeroq-service")) {
            return zeroqServiceRedirectUri;
        }
        if (clientId.endsWith("-zeroq-admin")) {
            return zeroqAdminRedirectUri;
        }
        if (clientId.endsWith("-semo")) {
            return semoRedirectUri;
        }
        if (clientId.endsWith("-stock")) {
            return stockRedirectUri;
        }

        return defaultRedirectUri;
    }
}
