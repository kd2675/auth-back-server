package auth.back.server.config;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;

class AuthCookieOriginFilterTest {

    private final AuthCookieOriginFilter filter = new AuthCookieOriginFilter(
            "https://stock.example.com,https://admin.example.com"
    );

    @Test
    void doFilter_refreshFromAllowedOrigin_continuesFilterChain() throws Exception {
        MockHttpServletRequest request = request("/auth/refresh", "https://stock.example.com");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertThat(chain.getRequest()).isSameAs(request);
    }

    @Test
    void doFilter_refreshFromUnknownOrigin_rejectsRequest() throws Exception {
        MockHttpServletRequest request = request("/auth/refresh", "https://attacker.example");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, new MockFilterChain());

        assertThat(response.getStatus()).isEqualTo(403);
    }

    private MockHttpServletRequest request(String path, String origin) {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", path);
        request.addHeader("Origin", origin);
        return request;
    }
}
