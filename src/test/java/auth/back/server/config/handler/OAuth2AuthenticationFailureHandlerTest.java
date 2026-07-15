package auth.back.server.config.handler;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.assertThat;

class OAuth2AuthenticationFailureHandlerTest {

    private final OAuth2AuthenticationFailureHandler handler = new OAuth2AuthenticationFailureHandler();

    @Test
    void onAuthenticationFailure_stockProvider_redirectsToStockLogin() throws Exception {
        ReflectionTestUtils.setField(handler, "defaultRedirectUri", "http://localhost:3001/login");
        ReflectionTestUtils.setField(handler, "museRedirectUri", "http://localhost:3000/login");
        ReflectionTestUtils.setField(handler, "zeroqServiceRedirectUri", "http://localhost:3001/login");
        ReflectionTestUtils.setField(handler, "zeroqAdminRedirectUri", "http://localhost:3002/login");
        ReflectionTestUtils.setField(handler, "semoRedirectUri", "http://localhost:3003/login");
        ReflectionTestUtils.setField(handler, "stockFailureRedirectUri", "http://localhost:3005/login");
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/login/oauth2/code/naver-stock");
        MockHttpServletResponse response = new MockHttpServletResponse();

        handler.onAuthenticationFailure(request, response, new BadCredentialsException("oauth failed"));

        assertThat(response.getRedirectedUrl()).startsWith("http://localhost:3005/login?error=");
    }
}
