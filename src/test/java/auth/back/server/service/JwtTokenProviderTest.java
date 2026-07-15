package auth.back.server.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;

class JwtTokenProviderTest {

    private static final String SECRET = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    private final JwtTokenProvider provider = new JwtTokenProvider();

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(provider, "jwtSecret", SECRET);
        ReflectionTestUtils.setField(provider, "accessTokenExpirationMs", 600_000L);
        ReflectionTestUtils.setField(provider, "refreshTokenExpirationMs", 18_000_000L);
        ReflectionTestUtils.setField(provider, "issuer", "https://auth.example.com");
    }

    @Test
    void generateAccessToken_stockClient_containsIssuerAudienceAndScopeBoundary() {
        String token = provider.generateAccessToken(
                "stock-user",
                "stock-user-key",
                "USER",
                "local",
                "stock-front-service"
        );

        Claims claims = Jwts.parser()
                .verifyWith(Keys.hmacShaKeyFor(SECRET.getBytes(StandardCharsets.UTF_8)))
                .requireIssuer("https://auth.example.com")
                .build()
                .parseSignedClaims(token)
                .getPayload();

        assertThat(claims.getAudience()).containsExactly("stock-api");
        assertThat(claims.get("client_id", String.class)).isEqualTo("stock-front-service");
        assertThat(claims.get("scope", String.class)).isEqualTo("api");
    }
}
