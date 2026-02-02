package auth.back.server.controller;

import auth.back.server.database.pub.entity.RefreshToken;
import auth.back.server.database.pub.entity.User;
import auth.back.server.service.JwtTokenProvider;
import auth.back.server.service.RefreshTokenService;
import auth.common.core.dto.LoginRequest;
import auth.common.core.dto.LoginResponse;
import auth.common.core.dto.TokenValidationResponse;
import auth.common.core.exception.AuthException;
import auth.common.core.exception.InvalidTokenException;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import web.common.core.response.base.dto.ResponseDataDTO;
import web.common.core.utils.CookieUtils;

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
    private final JwtTokenProvider jwtTokenProvider;
    private final RefreshTokenService refreshTokenService;

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
    public ResponseDataDTO<LoginResponse> login(@RequestBody LoginRequest request) {

        log.info("Login attempt for username: {}", request.getUsername());

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
                user.getId(),
                user.getRole()
        );
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(user);

        // Refresh Token을 HttpOnly 쿠키에 설정
        int maxAgeSeconds = (int) TimeUnit.MILLISECONDS.toSeconds(refreshTokenExpirationMs);
        CookieUtils.createCookie("refreshToken", refreshToken.getToken(), maxAgeSeconds);

        log.info("User {} logged in successfully", user.getUsername());

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
    public ResponseDataDTO<LoginResponse> refreshToken(
            @CookieValue(name = "refreshToken", required = false) String refreshTokenFromCookie) {

        log.info("Token refresh request");

        if (refreshTokenFromCookie == null || refreshTokenFromCookie.isEmpty()) {
            throw new AuthException("Refresh token not found in cookie");
        }

        RefreshToken refreshToken = refreshTokenService.findByToken(refreshTokenFromCookie)
                .orElseThrow(() -> new AuthException("Refresh token not found"));

        // 만료 확인 (만료 시 TokenExpiredException -> GlobalExceptionHandler)
        refreshTokenService.verifyExpiration(refreshToken);

        User user = refreshToken.getUser();
        String newAccessToken = jwtTokenProvider.generateAccessToken(
                user.getUsername(),
                user.getId(),
                user.getRole()
        );

        log.info("Token refreshed for user: {}", user.getUsername());

        LoginResponse loginResponse = LoginResponse.builder()
                .accessToken(newAccessToken)
                .tokenType("Bearer")
                .expiresIn(TimeUnit.MILLISECONDS.toSeconds(accessTokenExpirationMs))
                .build();

        return ResponseDataDTO.of(loginResponse, "Token refreshed");
    }

    /**
     * 로그아웃
     * - Gateway가 X-User-Id 헤더를 추가해서 보내줌
     * - Refresh Token 쿠키 삭제
     */
    @PostMapping("/logout")
    public ResponseDataDTO<Void> logout(
            @RequestHeader(value = "X-User-Id", required = false) String userIdHeader,
            @RequestHeader(value = "Authorization", required = false) String token) {

        if (userIdHeader != null && !userIdHeader.isEmpty()) {
            Long userId = Long.parseLong(userIdHeader);
            refreshTokenService.deleteByUserId(userId);
            log.info("User {} logged out successfully", userId);
        }

        log.debug("Logout - id: {}, token: {}", userIdHeader, token);

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
        Long userId = jwtTokenProvider.getUserIdFromToken(jwt);
        String role = jwtTokenProvider.getRoleFromToken(jwt);

        log.info("Token validated for user: {}", username);

        TokenValidationResponse response = TokenValidationResponse.builder()
                .valid(true)
                .username(username)
                .userId(userId)
                .role(role)
                .build();

        return ResponseDataDTO.of(response, "Token is valid");
    }
}
