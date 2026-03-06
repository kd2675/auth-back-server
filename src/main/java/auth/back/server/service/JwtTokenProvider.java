package auth.back.server.service;

import auth.back.server.database.pub.entity.User;
import auth.common.core.exception.InvalidTokenException;
import auth.common.core.exception.TokenExpiredException;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;

@Service
@Slf4j
public class JwtTokenProvider {

    @Value("${app.jwt.secret}")
    private String jwtSecret;

    @Value("${app.jwt.access-token-expiration-ms:900000}")
    private long accessTokenExpirationMs;

    @Value("${app.jwt.refresh-token-expiration-ms:604800000}")
    private long refreshTokenExpirationMs;

    /**
     * Access Token 생성
     */
    public String generateAccessToken(User user) {
        return generateAccessToken(user.getUsername(), user.getUserKey(), user.getRole());
    }

    public String generateAccessToken(String username, String userKey, String role) {
        return generateAccessToken(username, userKey, role, null, null);
    }

    public String generateAccessToken(User user, String loginType, String clientId) {
        return generateAccessToken(user.getUsername(), user.getUserKey(), user.getRole(), loginType, clientId);
    }

    public String generateAccessToken(
            String username,
            String userKey,
            String role,
            String loginType,
            String clientId
    ) {
        return createToken(username, userKey, role, loginType, clientId, accessTokenExpirationMs);
    }

    /**
     * Refresh Token 생성
     */
    public String generateRefreshToken(String username) {
        return createToken(username, null, null, null, null, refreshTokenExpirationMs);
    }

    /**
     * JWT 토큰 생성
     */
    private String createToken(
            String username,
            String userKey,
            String role,
            String loginType,
            String clientId,
            long expirationMs
    ) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + expirationMs);

        SecretKey key = Keys.hmacShaKeyFor(jwtSecret.getBytes());

        JwtBuilder builder = Jwts.builder()
                .subject(username)
                .issuedAt(now)
                .expiration(expiryDate)
                .signWith(key, SignatureAlgorithm.HS512);

        if (userKey != null) {
            builder.claim("userKey", userKey);
        }
        if (role != null) {
            builder.claim("role", role);
        }
        if (loginType != null) {
            builder.claim("loginType", loginType);
        }
        if (clientId != null) {
            builder.claim("clientId", clientId);
        }

        return builder.compact();
    }

    /**
     * 토큰에서 사용자명 추출
     */
    public String getUsernameFromToken(String token) {
        try {
            SecretKey key = Keys.hmacShaKeyFor(jwtSecret.getBytes());
            return Jwts.parser()
                    .verifyWith(key)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload()
                    .getSubject();
        } catch (ExpiredJwtException e) {
            throw new TokenExpiredException("Token has expired");
        } catch (JwtException | IllegalArgumentException e) {
            throw new InvalidTokenException("Invalid token");
        }
    }

    public String getUserKeyFromToken(String token) {
        try {
            SecretKey key = Keys.hmacShaKeyFor(jwtSecret.getBytes());
            Claims claims = Jwts.parser()
                    .verifyWith(key)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
            Object value = claims.get("userKey");
            return value instanceof String ? (String) value : null;
        } catch (ExpiredJwtException e) {
            throw new TokenExpiredException("Token has expired");
        } catch (JwtException | IllegalArgumentException e) {
            throw new InvalidTokenException("Invalid token");
        }
    }

    /**
     * 토큰에서 role 추출
     */
    public String getRoleFromToken(String token) {
        try {
            SecretKey key = Keys.hmacShaKeyFor(jwtSecret.getBytes());
            return Jwts.parser()
                    .verifyWith(key)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload()
                    .get("role", String.class);
        } catch (ExpiredJwtException e) {
            throw new TokenExpiredException("Token has expired");
        } catch (JwtException | IllegalArgumentException e) {
            throw new InvalidTokenException("Invalid token");
        }
    }

    /**
     * 토큰 유효성 검증
     */
    public boolean validateToken(String token) {
        try {
            SecretKey key = Keys.hmacShaKeyFor(jwtSecret.getBytes());
            Jwts.parser()
                    .verifyWith(key)
                    .build()
                    .parseSignedClaims(token);
            return true;
        } catch (ExpiredJwtException e) {
            log.warn("Token has expired: {}", e.getMessage());
            throw new TokenExpiredException("Token has expired");
        } catch (JwtException | IllegalArgumentException e) {
            log.warn("Invalid token: {}", e.getMessage());
            throw new InvalidTokenException("Invalid token");
        }
    }

    /**
     * Bearer 토큰에서 JWT 추출
     */
    public String extractTokenFromBearer(String bearerToken) {
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        throw new InvalidTokenException("Invalid bearer token format");
    }
}
