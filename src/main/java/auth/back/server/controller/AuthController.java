package auth.back.server.controller;

import auth.back.server.database.pub.entity.RefreshToken;
import auth.back.server.database.pub.entity.User;
import auth.back.server.database.pub.repository.UserRepository;
import auth.back.server.service.JwtTokenProvider;
import auth.back.server.service.RefreshTokenService;
import auth.back.server.service.UserService;
import auth.common.core.dto.LoginRequest;
import auth.common.core.dto.LoginResponse;
import auth.common.core.dto.RefreshTokenRequest;
import auth.common.core.dto.TokenValidationResponse;
import auth.common.core.exception.AuthException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
@Slf4j
@CrossOrigin(origins = "*", maxAge = 3600)
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider jwtTokenProvider;
    private final RefreshTokenService refreshTokenService;
    private final UserService userService;
    private final UserRepository userRepository;

    /**
     * 로그인
     */
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request) {
        try {
            log.info("Login attempt for username: {}", request.getUsername());

            // 사용자 인증
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

            log.info("User {} logged in successfully", user.getUsername());

            return ResponseEntity.ok(LoginResponse.builder()
                    .accessToken(accessToken)
                    .refreshToken(refreshToken.getToken())
                    .tokenType("Bearer")
                    .expiresIn(900)
                    .build());

        } catch (Exception e) {
            log.error("Login failed: {}", e.getMessage());
            return ResponseEntity.status(401).body(
                    Map.of("error", "Invalid credentials")
            );
        }
    }

    /**
     * 토큰 갱신
     */
    @PostMapping("/refresh")
    public ResponseEntity<?> refreshToken(@RequestBody RefreshTokenRequest request) {
        try {
            log.info("Token refresh request");

            String requestRefreshToken = request.getRefreshToken();

            RefreshToken refreshToken = refreshTokenService.findByToken(requestRefreshToken)
                    .orElseThrow(() -> new AuthException("Refresh token not found"));

            refreshTokenService.verifyExpiration(refreshToken);

            User user = refreshToken.getUser();
            String newAccessToken = jwtTokenProvider.generateAccessToken(
                    user.getUsername(),
                    user.getId(),
                    user.getRole()
            );

            log.info("Token refreshed for user: {}", user.getUsername());

            return ResponseEntity.ok(LoginResponse.builder()
                    .accessToken(newAccessToken)
                    .refreshToken(requestRefreshToken)
                    .tokenType("Bearer")
                    .expiresIn(900)
                    .build());

        } catch (Exception e) {
            log.error("Token refresh failed: {}", e.getMessage());
            return ResponseEntity.status(401).body(
                    Map.of("error", e.getMessage())
            );
        }
    }

    /**
     * 로그아웃
     */
    @PostMapping("/logout")
    public ResponseEntity<?> logout(@RequestHeader(value = "Authorization", required = false) String token) {
        try {
            if (token != null && token.startsWith("Bearer ")) {
                String jwt = token.substring(7);
                String username = jwtTokenProvider.getUsernameFromToken(jwt);

                User user = userRepository.findByUsername(username)
                        .orElseThrow(() -> new AuthException("User not found"));

                refreshTokenService.deleteByUser(user);

                log.info("User {} logged out successfully", username);
            }

            return ResponseEntity.ok(Map.of("message", "User logged out successfully"));

        } catch (Exception e) {
            log.error("Logout failed: {}", e.getMessage());
            return ResponseEntity.status(400).body(
                    Map.of("error", "Logout failed")
            );
        }
    }

    /**
     * 토큰 검증 (내부 서비스용)
     */
    @PostMapping("/validate")
    public ResponseEntity<?> validateToken(@RequestHeader(value = "Authorization", required = false) String token) {
        try {
            if (token == null || !token.startsWith("Bearer ")) {
                return ResponseEntity.status(401).body(
                        Map.of("valid", false, "message", "Invalid token format")
                );
            }

            String jwt = token.substring(7);

            if (jwtTokenProvider.validateToken(jwt)) {
                String username = jwtTokenProvider.getUsernameFromToken(jwt);
                Long userId = jwtTokenProvider.getUserIdFromToken(jwt);
                String role = jwtTokenProvider.getRoleFromToken(jwt);

                log.info("Token validated for user: {}", username);

                return ResponseEntity.ok(TokenValidationResponse.builder()
                        .valid(true)
                        .username(username)
                        .userId(userId)
                        .role(role)
                        .build());
            }

            return ResponseEntity.status(401).body(
                    Map.of("valid", false, "message", "Token is invalid")
            );

        } catch (Exception e) {
            log.error("Token validation failed: {}", e.getMessage());
            return ResponseEntity.status(401).body(
                    TokenValidationResponse.builder()
                            .valid(false)
                            .build()
            );
        }
    }

    /**
     * 공개키 제공 (API Gateway 용)
     */
    @GetMapping("/.well-known/jwks.json")
    public ResponseEntity<?> getJwks() {
        // 나중에 구현 (선택사항)
        return ResponseEntity.ok(Map.of(
                "keys", new Object[0]
        ));
    }
}
