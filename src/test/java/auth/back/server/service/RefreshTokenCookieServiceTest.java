package auth.back.server.service;

import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

class RefreshTokenCookieServiceTest {

    @Test
    void write_productionPolicy_setsRestrictedSecureCookieAttributes() {
        RefreshTokenCookieService service = new RefreshTokenCookieService(
                "refreshToken",
                "/auth",
                "Lax",
                true
        );
        MockHttpServletResponse response = new MockHttpServletResponse();

        service.write(response, "refresh-value", Duration.ofHours(5));

        assertThat(response.getHeader("Set-Cookie"))
                .contains("refreshToken=refresh-value")
                .contains("Path=/auth")
                .contains("Max-Age=18000")
                .contains("Secure")
                .contains("HttpOnly")
                .contains("SameSite=Lax");
    }

    @Test
    void delete_usesSameScopeAndExpiresCookieImmediately() {
        RefreshTokenCookieService service = new RefreshTokenCookieService(
                "refreshToken",
                "/auth",
                "Lax",
                true
        );
        MockHttpServletResponse response = new MockHttpServletResponse();

        service.delete(response);

        assertThat(response.getHeader("Set-Cookie"))
                .contains("refreshToken=")
                .contains("Path=/auth")
                .contains("Max-Age=0")
                .contains("Secure")
                .contains("HttpOnly")
                .contains("SameSite=Lax");
    }

    @Test
    void write_clientId_usesIsolatedCookieAndDeletesLegacyCookie() {
        RefreshTokenCookieService service = new RefreshTokenCookieService(
                "refreshToken",
                "/auth",
                "Lax",
                true
        );
        MockHttpServletResponse response = new MockHttpServletResponse();

        service.write(response, "naver-semo", "semo-refresh", Duration.ofHours(5));

        assertThat(response.getHeaders("Set-Cookie"))
                .anySatisfy(cookie -> assertThat(cookie)
                        .contains("refreshToken-semo-front-service=semo-refresh")
                        .contains("Max-Age=18000"))
                .anySatisfy(cookie -> assertThat(cookie)
                        .contains("refreshToken=")
                        .contains("Max-Age=0"));
    }

    @Test
    void read_clientId_selectsMatchingCookieAndFallsBackToLegacy() {
        RefreshTokenCookieService service = new RefreshTokenCookieService(
                "refreshToken",
                "/auth",
                "Lax",
                true
        );
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setCookies(
                new Cookie("refreshToken-muse-front-service", "muse-refresh"),
                new Cookie("refreshToken-semo-front-service", "semo-refresh"),
                new Cookie("refreshToken", "legacy-refresh")
        );

        assertThat(service.read(request, "muse-front-service")).isEqualTo("muse-refresh");
        assertThat(service.read(request, "kakao-semo")).isEqualTo("semo-refresh");
        assertThat(service.read(request, "unknown-client")).isEqualTo("legacy-refresh");
    }
}
