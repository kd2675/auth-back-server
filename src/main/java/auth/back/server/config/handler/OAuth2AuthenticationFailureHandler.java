package auth.back.server.config.handler;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;

@Component
public class OAuth2AuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {

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

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException {
        String clientId = resolveClientId(request.getRequestURI());
        String targetUrl = UriComponentsBuilder.fromUriString(resolveFrontRedirectUri(clientId))
                .queryParam("error", exception.getLocalizedMessage())
                .build().toUriString();

        getRedirectStrategy().sendRedirect(request, response, targetUrl);
    }

    private String resolveClientId(String requestUri) {
        if (requestUri == null) {
            return "";
        }
        int lastSlash = requestUri.lastIndexOf('/');
        if (lastSlash < 0 || lastSlash + 1 >= requestUri.length()) {
            return "";
        }
        return requestUri.substring(lastSlash + 1);
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

        return defaultRedirectUri;
    }
}
