package auth.back.server.controller;

import auth.back.server.database.pub.entity.AuthAuthorization;
import auth.back.server.database.pub.entity.AuthRegisteredClient;
import auth.back.server.database.pub.entity.RefreshToken;
import auth.back.server.database.pub.entity.User;
import auth.back.server.service.AuthAuthorizationService;
import auth.back.server.service.AuthRegisteredClientService;
import auth.back.server.service.JwtTokenProvider;
import auth.back.server.service.RefreshTokenService;
import auth.back.server.service.oauth2.OAuth2AuthorizationRevocationService;
import auth.common.core.dto.LoginRequest;
import auth.common.core.dto.LoginResponse;
import auth.common.core.dto.TokenValidationResponse;
import auth.common.core.exception.AuthException;
import auth.common.core.exception.InvalidTokenException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import web.common.core.response.base.dto.ResponseDataDTO;
import web.common.core.utils.CookieUtils;
import org.springframework.util.StringUtils;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

/**
 * Auth Controller - 인증/인가 전용 컨트롤러
 *
 * Gateway Offloading 패턴:
 * - JWT 검증은 Gateway(cloud-back-server)에서 수행
 * - Auth Service는 토큰 발급/관리만 담당
 *
 * 엔드포인트:
 * - POST /auth/login        : 로그인 (토큰 발급)
 * - POST /auth/logout       : 로그아웃 (토큰 무효화)
 * - POST /auth/refresh      : Access Token 갱신
 * - POST /auth/validate     : 토큰 검증 (내부 서비스용)
 */
@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final AuthAuthorizationService authAuthorizationService;
    private final AuthRegisteredClientService authRegisteredClientService;
    private final JwtTokenProvider jwtTokenProvider;
    private final RefreshTokenService refreshTokenService;
    private final OAuth2AuthorizationRevocationService oAuth2AuthorizationRevocationService;

    @Value("${app.jwt.access-token-expiration-ms:3600000}")
    private long accessTokenExpirationMs;

    @Value("${app.jwt.refresh-token-expiration-ms:1209600000}")
    private long refreshTokenExpirationMs;

    /**
     * 로그인
     * - Access Token은 응답 바디로 반환
     * - Refresh Token은 HttpOnly 쿠키에 설정
     */
    @PostMapping("/login")
    public ResponseDataDTO<LoginResponse> login(
            @RequestHeader(value = "X-Client-Id", required = false) String clientIdHeader,
            @RequestBody LoginRequest request) {

        AuthRegisteredClient registeredClient = authRegisteredClientService.validateActiveClient(clientIdHeader);
        String clientId = registeredClient.getClientId();

        log.info("Login attempt for username: {}, clientId: {}", request.getUsername(), clientId);

        // 사용자 인증 (실패 시 BadCredentialsException 발생 -> GlobalExceptionHandler)
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getUsername(),
                        request.getPassword()
                )
        );

        SecurityContextHolder.getContext().setAuthentication(authentication);
        User user = (User) authentication.getPrincipal();

        // 토큰 생성
        String accessToken = jwtTokenProvider.generateAccessToken(
                user.getUsername(),
                user.getUserKey(),
                user.getRole(),
                "local",
                clientId
        );
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(user);
        LocalDateTime accessTokenIssuedAt = LocalDateTime.now();
        LocalDateTime accessTokenExpiresAt = accessTokenIssuedAt.plus(Duration.ofMillis(accessTokenExpirationMs));
        LocalDateTime refreshTokenIssuedAt = LocalDateTime.now();

        authAuthorizationService.saveLoginAuthorization(
                registeredClient,
                user,
                accessToken,
                accessTokenIssuedAt,
                accessTokenExpiresAt,
                refreshToken.getToken(),
                refreshTokenIssuedAt,
                refreshToken.getExpiryDate()
        );

        // Refresh Token을 HttpOnly 쿠키에 설정
        int maxAgeSeconds = (int) TimeUnit.MILLISECONDS.toSeconds(refreshTokenExpirationMs);
        CookieUtils.createCookie("refreshToken", refreshToken.getToken(), maxAgeSeconds);

        log.info("User {} logged in successfully for clientId {}", user.getUsername(), clientId);

        // Access Token만 응답 바디로 반환 (Refresh Token은 쿠키에 있음)
        LoginResponse loginResponse = LoginResponse.builder()
                .accessToken(accessToken)
                .tokenType("Bearer")
                .expiresIn(TimeUnit.MILLISECONDS.toSeconds(accessTokenExpirationMs))
                .build();

        return ResponseDataDTO.of(loginResponse, "Login successful");
    }

    /**
     * 토큰 갱신
     * - Refresh Token은 HttpOnly 쿠키에서 읽음
     */
    @PostMapping("/refresh")
    public ResponseEntity<ResponseDataDTO<LoginResponse>> refreshToken(
            @CookieValue(name = "refreshToken", required = false) String refreshTokenFromCookie) {

        log.info("Token refresh request");

        try {
            String refreshTokenValue = requireRefreshToken(refreshTokenFromCookie);

            Optional<ResponseEntity<ResponseDataDTO<LoginResponse>>> localRefreshResult =
                    tryRefreshLocalToken(refreshTokenValue);

            if (localRefreshResult.isPresent()) {
                return localRefreshResult.get();
            }

            return refreshOAuth2Token(refreshTokenValue);
        } catch (AuthException ex) {
            CookieUtils.deleteCookie("refreshToken");
            return ResponseEntity.noContent().build();
        }
    }

    private String requireRefreshToken(String refreshTokenFromCookie) {
        if (!StringUtils.hasText(refreshTokenFromCookie)) {
            throw new AuthException("Refresh token not found in cookie");
        }
        return refreshTokenFromCookie;
    }

    private Optional<ResponseEntity<ResponseDataDTO<LoginResponse>>> tryRefreshLocalToken(String refreshTokenValue) {
        return authAuthorizationService.findByRefreshToken(refreshTokenValue)
                .map(localAuthorization -> refreshLocalToken(refreshTokenValue, localAuthorization));
    }

    private ResponseEntity<ResponseDataDTO<LoginResponse>> refreshLocalToken(
            String refreshTokenValue,
            AuthAuthorization localAuthorization
    ) {
        validateLocalAuthorization(localAuthorization);

        RefreshToken refreshToken = loadVerifiedRefreshToken(refreshTokenValue);
        User user = refreshToken.getUser();
        String clientId = authAuthorizationService.resolveClientId(localAuthorization);
        String newAccessToken = jwtTokenProvider.generateAccessToken(
                user.getUsername(),
                user.getUserKey(),
                user.getRole(),
                "local",
                clientId
        );

        LocalDateTime accessTokenIssuedAt = LocalDateTime.now();
        LocalDateTime accessTokenExpiresAt = accessTokenIssuedAt.plus(Duration.ofMillis(accessTokenExpirationMs));
        authAuthorizationService.updateAccessToken(
                localAuthorization,
                newAccessToken,
                accessTokenIssuedAt,
                accessTokenExpiresAt
        );

        log.info("Token refreshed for local user: {}, clientId: {}", user.getUsername(), clientId);
        return buildRefreshSuccessResponse(newAccessToken);
    }

    private void validateLocalAuthorization(AuthAuthorization localAuthorization) {
        if (Boolean.TRUE.equals(localAuthorization.getInvalidated())) {
            throw new AuthException("Refresh token has been revoked");
        }
        if (localAuthorization.getRefreshTokenExpiresAt().isBefore(LocalDateTime.now())) {
            throw new AuthException("Refresh token has expired");
        }
    }

    private ResponseEntity<ResponseDataDTO<LoginResponse>> refreshOAuth2Token(String refreshTokenValue) {
        validateOAuth2RefreshToken(refreshTokenValue);

        RefreshToken refreshToken = loadVerifiedRefreshToken(refreshTokenValue);
        User user = refreshToken.getUser();
        String newAccessToken = jwtTokenProvider.generateAccessToken(
                user.getUsername(),
                user.getUserKey(),
                user.getRole(),
                "oauth2",
                null
        );

        log.info("Token refreshed for user: {}", user.getUsername());
        return buildRefreshSuccessResponse(newAccessToken);
    }

    private void validateOAuth2RefreshToken(String refreshTokenValue) {
        if (!oAuth2AuthorizationRevocationService.hasRefreshToken(refreshTokenValue)) {
            throw new AuthException("Refresh token not found");
        }
        if (oAuth2AuthorizationRevocationService.isRefreshTokenInvalidated(refreshTokenValue)) {
            throw new AuthException("Refresh token has been revoked");
        }
        if (oAuth2AuthorizationRevocationService.isRefreshTokenExpired(refreshTokenValue)) {
            throw new AuthException("Refresh token has expired");
        }
    }

    private RefreshToken loadVerifiedRefreshToken(String refreshTokenValue) {
        RefreshToken refreshToken = refreshTokenService.findByToken(refreshTokenValue)
                .orElseThrow(() -> new AuthException("Refresh token not found"));
        return refreshTokenService.verifyExpiration(refreshToken);
    }

    private ResponseEntity<ResponseDataDTO<LoginResponse>> buildRefreshSuccessResponse(String accessToken) {
        LoginResponse loginResponse = LoginResponse.builder()
                .accessToken(accessToken)
                .tokenType("Bearer")
                .expiresIn(TimeUnit.MILLISECONDS.toSeconds(accessTokenExpirationMs))
                .build();

        return ResponseEntity.ok(ResponseDataDTO.of(loginResponse, "Token refreshed"));
    }

    /**
     * 로그아웃
     * - Gateway가 X-User-Key 헤더를 추가해서 보내줌
     * - Refresh Token 쿠키 삭제
     */
    @PostMapping("/logout")
    public ResponseDataDTO<Void> logout(
            @RequestHeader(value = "X-User-Key", required = false) String userKeyHeader,
            @RequestHeader(value = "Authorization", required = false) String token,
            @CookieValue(name = "refreshToken", required = false) String refreshTokenFromCookie) {

        log.info("Logout request");

        if (StringUtils.hasText(token) && token.startsWith("Bearer ")) {
            authAuthorizationService.invalidateByAccessToken(token.substring(7));
            oAuth2AuthorizationRevocationService.invalidateByAccessToken(token.substring(7));
        }

        if (StringUtils.hasText(refreshTokenFromCookie)) {
            authAuthorizationService.invalidateByRefreshToken(refreshTokenFromCookie);
            oAuth2AuthorizationRevocationService.invalidateByRefreshToken(refreshTokenFromCookie);
        }

        if (userKeyHeader != null && !userKeyHeader.isEmpty()) {
            refreshTokenService.deleteByUserKey(userKeyHeader);
            log.info("User {} logged out successfully", userKeyHeader);
        }

        log.debug("Logout - userKey: {}, token: {}", userKeyHeader, token);

        // Refresh Token 쿠키 삭제
        CookieUtils.deleteCookie("refreshToken");

        return ResponseDataDTO.of(null, "Logged out successfully");
    }

    /**
     * 토큰 검증 (내부 서비스용)
     */
    @PostMapping("/validate")
    public ResponseDataDTO<TokenValidationResponse> validateToken(
            @RequestHeader(value = "Authorization", required = false) String token) {

        if (token == null || !token.startsWith("Bearer ")) {
            throw new InvalidTokenException("Invalid token format");
        }

        String jwt = token.substring(7);

        // 검증 실패 시 예외 발생 -> GlobalExceptionHandler
        jwtTokenProvider.validateToken(jwt);

        String username = jwtTokenProvider.getUsernameFromToken(jwt);
        String userKey = jwtTokenProvider.getUserKeyFromToken(jwt);
        String role = jwtTokenProvider.getRoleFromToken(jwt);

        log.info("Token validated for user: {}", username);

        TokenValidationResponse response = TokenValidationResponse.builder()
                .valid(true)
                .username(username)
                .userKey(userKey)
                .role(role)
                .build();

        return ResponseDataDTO.of(response, "Token is valid");
    }
}
