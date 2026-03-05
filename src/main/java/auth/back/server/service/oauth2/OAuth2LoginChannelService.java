package auth.back.server.service.oauth2;

import auth.common.core.exception.AuthException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import web.common.core.utils.CookieUtils;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

@Service
public class OAuth2LoginChannelService {
    public static final String CHANNEL_ZEROQ_FRONT_SERVICE = "zeroq-front-service";
    public static final String CHANNEL_MUSE_FRONT_SERVICE = "muse-front-service";
    public static final String CHANNEL_SEMO_FRONT_SERVICE = "semo-front-service";
    public static final String CHANNEL_ZEROQ_FRONT_ADMIN = "zeroq-front-admin";

    private static final String CHANNEL_COOKIE_NAME = "oauth2_login_channel";
    private static final int CHANNEL_COOKIE_MAX_AGE_SECONDS = 300;

    @Value("${app.oauth2.channel.zeroq-front-service.redirect-uri:http://localhost:3003/login}")
    private String zeroqFrontServiceRedirectUri;

    @Value("${app.oauth2.channel.muse-front-service.redirect-uri:http://localhost:3001/login}")
    private String museFrontServiceRedirectUri;

    @Value("${app.oauth2.channel.semo-front-service.redirect-uri:http://localhost:3000/login}")
    private String semoFrontServiceRedirectUri;

    @Value("${app.oauth2.channel.zeroq-front-admin.redirect-uri:http://localhost:3002/login}")
    private String zeroqFrontAdminRedirectUri;

    public String normalizeOrThrow(String channel) {
        if (channel == null || channel.isBlank()) {
            return CHANNEL_ZEROQ_FRONT_SERVICE;
        }

        String normalized = channel.trim().toLowerCase(Locale.ROOT);
        if (getAllowedRedirectMap().containsKey(normalized)) {
            return normalized;
        }

        throw new AuthException("Unsupported oauth2 channel: " + channel);
    }

    public void rememberChannel(String channel) {
        CookieUtils.createCookie(CHANNEL_COOKIE_NAME, normalizeOrThrow(channel), CHANNEL_COOKIE_MAX_AGE_SECONDS);
    }

    public String resolveFromRequest(HttpServletRequest request) {
        if (request == null || request.getCookies() == null) {
            return CHANNEL_ZEROQ_FRONT_SERVICE;
        }

        for (Cookie cookie : request.getCookies()) {
            if (!CHANNEL_COOKIE_NAME.equals(cookie.getName())) {
                continue;
            }
            try {
                String value = URLDecoder.decode(cookie.getValue(), StandardCharsets.UTF_8);
                return normalizeOrThrow(value);
            } catch (Exception ignored) {
                return CHANNEL_ZEROQ_FRONT_SERVICE;
            }
        }
        return CHANNEL_ZEROQ_FRONT_SERVICE;
    }

    public void clearRememberedChannel() {
        CookieUtils.deleteCookie(CHANNEL_COOKIE_NAME);
    }

    public String resolveRedirectUri(String channel) {
        String normalized = normalizeOrThrow(channel);
        String redirectUri = getAllowedRedirectMap().get(normalized);
        if (redirectUri == null || redirectUri.isBlank()) {
            throw new AuthException("OAuth redirect uri is not configured for channel: " + normalized);
        }
        return redirectUri;
    }

    private Map<String, String> getAllowedRedirectMap() {
        Map<String, String> redirectMap = new LinkedHashMap<>();
        redirectMap.put(CHANNEL_ZEROQ_FRONT_SERVICE, zeroqFrontServiceRedirectUri);
        redirectMap.put(CHANNEL_MUSE_FRONT_SERVICE, museFrontServiceRedirectUri);
        redirectMap.put(CHANNEL_SEMO_FRONT_SERVICE, semoFrontServiceRedirectUri);
        redirectMap.put(CHANNEL_ZEROQ_FRONT_ADMIN, zeroqFrontAdminRedirectUri);
        return redirectMap;
    }
}

