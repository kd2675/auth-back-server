package auth.back.server.service;

import java.time.Duration;
import java.util.Arrays;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Service;

@Service
public class RefreshTokenCookieService {

    private final String cookieName;
    private final String cookiePath;
    private final String sameSite;
    private final boolean secure;

    public RefreshTokenCookieService(
            @Value("${app.auth.refresh-cookie.name:refreshToken}") String cookieName,
            @Value("${app.auth.refresh-cookie.path:/auth}") String cookiePath,
            @Value("${app.auth.refresh-cookie.same-site:Lax}") String sameSite,
            @Value("${app.auth.refresh-cookie.secure:false}") boolean secure
    ) {
        this.cookieName = cookieName;
        this.cookiePath = cookiePath;
        this.sameSite = sameSite;
        this.secure = secure;
    }

    public void write(HttpServletResponse response, String value, Duration maxAge) {
        response.addHeader(HttpHeaders.SET_COOKIE, build(cookieName, value, maxAge).toString());
    }

    /** clientId별 쿠키를 쓰고 이전 단일 이름 쿠키는 제거해 서비스 간 세션 충돌을 막는다. */
    public void write(HttpServletResponse response, String clientId, String value, Duration maxAge) {
        response.addHeader(HttpHeaders.SET_COOKIE, build(resolveCookieName(clientId), value, maxAge).toString());
        deleteLegacyCookie(response);
    }

    public void delete(HttpServletResponse response) {
        deleteCookie(response, cookieName);
    }

    /** 현재 client 쿠키와 legacy 쿠키를 Max-Age=0으로 만료시킨다. */
    public void delete(HttpServletResponse response, String clientId) {
        deleteCookie(response, resolveCookieName(clientId));
        deleteLegacyCookie(response);
    }

    /** client별 쿠키를 우선 읽고 이전 배포와의 호환을 위해 legacy 이름을 fallback으로 읽는다. */
    public String read(HttpServletRequest request, String clientId) {
        if (request.getCookies() == null) {
            return null;
        }
        String clientCookieName = resolveCookieName(clientId);
        return Arrays.stream(request.getCookies())
                .filter(cookie -> clientCookieName.equals(cookie.getName()))
                .map(Cookie::getValue)
                .findFirst()
                .orElseGet(() -> Arrays.stream(request.getCookies())
                        .filter(cookie -> cookieName.equals(cookie.getName()))
                        .map(Cookie::getValue)
                        .findFirst()
                        .orElse(null));
    }

    /** OAuth registration id와 프런트 client id를 동일한 서비스별 쿠키 이름으로 정규화한다. */
    public String resolveCookieName(String clientId) {
        String canonicalClientId = canonicalClientId(clientId);
        if (canonicalClientId.isEmpty()) {
            return cookieName;
        }
        return cookieName + "-" + canonicalClientId.replaceAll("[^A-Za-z0-9_-]", "_");
    }

    private String canonicalClientId(String clientId) {
        if (clientId == null || clientId.isBlank()) {
            return "";
        }
        if (clientId.equals("muse-front-service") || clientId.endsWith("-muse")) {
            return "muse-front-service";
        }
        if (clientId.equals("zeroq-front-service") || clientId.endsWith("-zeroq-service")) {
            return "zeroq-front-service";
        }
        if (clientId.equals("zeroq-front-admin") || clientId.endsWith("-zeroq-admin")) {
            return "zeroq-front-admin";
        }
        if (clientId.equals("semo-front-service") || clientId.endsWith("-semo")) {
            return "semo-front-service";
        }
        if (clientId.equals("stock-front-service") || clientId.endsWith("-stock")) {
            return "stock-front-service";
        }
        return clientId.trim();
    }

    private void deleteLegacyCookie(HttpServletResponse response) {
        deleteCookie(response, cookieName);
    }

    private void deleteCookie(HttpServletResponse response, String targetCookieName) {
        response.addHeader(HttpHeaders.SET_COOKIE, build(targetCookieName, "", Duration.ZERO).toString());
    }

    private ResponseCookie build(String targetCookieName, String value, Duration maxAge) {
        return ResponseCookie.from(targetCookieName, value)
                .httpOnly(true)
                .secure(secure)
                .sameSite(sameSite)
                .path(cookiePath)
                .maxAge(maxAge)
                .build();
    }
}
