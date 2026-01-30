package auth.back.server.config;

import auth.back.server.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Auth Service Security 설정
 *
 * Gateway Offloading 패턴:
 * - JWT 검증은 Gateway(cloud-back-server)에서 수행
 * - Auth Service는 토큰 발급/관리만 담당
 * - 모든 요청은 Gateway를 통해 들어오므로 permitAll()
 *
 * 역할:
 * - 로그인 시 비밀번호 검증 (AuthenticationManager, UserDetailsService)
 * - JWT 토큰 생성 (JwtTokenProvider)
 * - Refresh Token 관리
 */
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfiguration {

    private final UserService userService;

    /**
     * AuthenticationManager Bean 등록
     * - 로그인 시 비밀번호 검증에 사용
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    /**
     * Security Filter Chain
     *
     * Gateway가 JWT를 검증하고 X-User-Id, X-User-Role 헤더를 추가해서 보내므로
     * Auth Service에서는 별도의 인증 필터가 필요 없음
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .authorizeHttpRequests(authz -> authz
                        // Gateway가 인증을 처리하므로 모든 요청 허용
                        // 실제 인증 검사는 Gateway의 JwtAuthenticationFilter에서 수행
                        .anyRequest().permitAll()
                )
                // 로그인 시 비밀번호 검증을 위해 UserDetailsService 등록
                .userDetailsService(userService);

        return http.build();
    }
}
