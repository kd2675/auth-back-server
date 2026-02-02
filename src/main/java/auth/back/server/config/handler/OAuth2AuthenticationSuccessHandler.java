package auth.back.server.config.handler;

import auth.back.server.database.pub.entity.RefreshToken;
import auth.back.server.database.pub.entity.User;
import auth.back.server.service.JwtTokenProvider;
import auth.back.server.service.RefreshTokenService;
import auth.back.server.service.oauth2.UserPrincipal;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.util.concurrent.TimeUnit;

@Component
@RequiredArgsConstructor
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final JwtTokenProvider jwtTokenProvider;
    private final RefreshTokenService refreshTokenService;

    @Value("${app.oauth2.client.service.redirect-uri}")
    private String redirectUri;
    
    @Value("${app.jwt.refresh-token-expiration-ms:1209600000}")
    private long refreshTokenExpirationMs;

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

        String accessToken = jwtTokenProvider.generateAccessToken(user);
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(user);

        Cookie refreshTokenCookie = new Cookie("refreshToken", refreshToken.getToken());
        refreshTokenCookie.setHttpOnly(true);
        refreshTokenCookie.setSecure(false); // HTTPS에서는 true로 설정
        refreshTokenCookie.setPath("/");
        refreshTokenCookie.setMaxAge((int) TimeUnit.MILLISECONDS.toSeconds(refreshTokenExpirationMs));
        response.addCookie(refreshTokenCookie);
        
        return UriComponentsBuilder.fromUriString(redirectUri)
                .queryParam("token", accessToken)
                .build().toUriString();
    }
}
