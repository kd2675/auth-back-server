package auth.back.server.config;

import static org.springframework.security.config.Customizer.withDefaults;

import auth.back.server.config.handler.OAuth2AuthenticationFailureHandler;
import auth.back.server.config.handler.OAuth2AuthenticationSuccessHandler;
import auth.back.server.service.oauth2.CustomOAuth2UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.http.HttpMethod;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfiguration {

    private final CustomOAuth2UserService customOAuth2UserService;
    private final OAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler;
    private final OAuth2AuthenticationFailureHandler oAuth2AuthenticationFailureHandler;

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    @Order(100) // Lower precedence than the auto-configured Authorization Server chain
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                            .authorizeHttpRequests(authorize -> authorize
                                .requestMatchers("/auth/login", "/auth/refresh", "/login/**").permitAll()
                                .requestMatchers(HttpMethod.POST, "/api/users").permitAll()
                                .anyRequest().authenticated()
                            )                .oauth2Login(oauth2 -> oauth2
                        .authorizationEndpoint(endpoint -> endpoint.baseUri("/oauth2/authorize"))
                        .redirectionEndpoint(endpoint -> endpoint.baseUri("/login/oauth2/code/*"))
                        .successHandler(oAuth2AuthenticationSuccessHandler)
                        .failureHandler(oAuth2AuthenticationFailureHandler)
                        .userInfoEndpoint(endpoint -> endpoint.userService(customOAuth2UserService))
                );

        return http.build();
    }
}

