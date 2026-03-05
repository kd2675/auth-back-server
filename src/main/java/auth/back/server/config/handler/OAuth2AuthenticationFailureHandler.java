package auth.back.server.config.handler;

import auth.back.server.service.oauth2.OAuth2LoginChannelService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;

@Component
@RequiredArgsConstructor
@Slf4j
public class OAuth2AuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {
    private final OAuth2LoginChannelService oauth2LoginChannelService;

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception)
            throws IOException {
        String channel = oauth2LoginChannelService.resolveFromRequest(request);
        String redirectUri = oauth2LoginChannelService.resolveRedirectUri(channel);
        oauth2LoginChannelService.clearRememberedChannel();

        log.warn("OAuth2 BFF login failed. channel={}, error={}", channel, exception.getMessage());
        String targetUrl = UriComponentsBuilder.fromUriString(redirectUri)
                .queryParam("oauthError", "1")
                .build()
                .toUriString();
        getRedirectStrategy().sendRedirect(request, response, targetUrl);
    }
}

