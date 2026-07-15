package auth.back.server.service;

import org.junit.jupiter.api.Test;
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
}
