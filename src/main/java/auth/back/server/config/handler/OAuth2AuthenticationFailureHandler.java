package auth.back.server.config.handler;

import auth.common.core.exception.OAuth2AuthenticationProcessingException;
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
        OAuth2AuthenticationProcessingException oauth2Error = findOAuth2Error(exception);

        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(resolveFrontRedirectUri(clientId))
                .queryParam("error", exception.getLocalizedMessage());

        if (oauth2Error != null && oauth2Error.getErrorCode() != null) {
            builder.queryParam("errorCode", oauth2Error.getErrorCode());
        }
        if (oauth2Error != null && oauth2Error.getProviderHint() != null) {
            builder.queryParam("provider", oauth2Error.getProviderHint());
        }

        String targetUrl = builder.build().toUriString();

        getRedirectStrategy().sendRedirect(request, response, targetUrl);
    }

    private OAuth2AuthenticationProcessingException findOAuth2Error(Throwable throwable) {
        Throwable current = throwable;
        while (current != null) {
            if (current instanceof OAuth2AuthenticationProcessingException oauth2Exception) {
                return oauth2Exception;
            }
            current = current.getCause();
        }
        return null;
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
