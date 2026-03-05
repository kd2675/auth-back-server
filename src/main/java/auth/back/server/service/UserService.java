package auth.back.server.service;

import auth.back.server.database.pub.entity.User;
import auth.back.server.database.pub.repository.UserRepository;
import auth.common.core.constant.Provider;
import auth.common.core.constant.UserRole;
import auth.common.core.exception.AuthException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Set;

@Service
@RequiredArgsConstructor
@Transactional
@Slf4j
public class UserService implements UserDetailsService {

    private static final Set<String> SIGNUP_ALLOWED_ROLES = Set.of(
            UserRole.USER,
            UserRole.MANAGER
    );

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Value("${app.signup.manager-secret:1234}")
    private String managerSignupSecret;

    /**
     * UserDetailsService 구현
     */
    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));
    }

    /**
     * 사용자 등록
     */
    public User registerUser(String username, String password, String email) {
        return registerUser(username, password, email, UserRole.USER, null);
    }

    /**
     * 사용자 등록 (역할 지정)
     * - 공개 회원가입에서는 USER, MANAGER만 허용
     */
    public User registerUser(String username, String password, String email, String role) {
        return registerUser(username, password, email, role, null);
    }

    /**
     * 사용자 등록 (역할 + 가입 비밀번호)
     * - MANAGER 가입은 서버 설정값(app.signup.manager-secret)과 일치해야 함
     */
    public User registerUser(String username, String password, String email, String role, String signupSecret) {
        if (userRepository.existsByUsername(username)) {
            throw new AuthException("Username already exists");
        }
        if (userRepository.existsByEmail(email)) {
            throw new AuthException("Email already exists");
        }

        String normalizedRole = UserRole.normalize(role);
        if (!SIGNUP_ALLOWED_ROLES.contains(normalizedRole)) {
            throw new AuthException("Invalid role. Allowed: USER, MANAGER");
        }
        if (UserRole.MANAGER.equals(normalizedRole)) {
            String requestSecret = signupSecret == null ? "" : signupSecret.trim();
            String requiredSecret = managerSignupSecret == null ? "" : managerSignupSecret.trim();
            if (requiredSecret.isEmpty() || !requiredSecret.equals(requestSecret)) {
                throw new AuthException("Invalid manager signup secret");
            }
        }

        User user = User.builder()
                .username(username)
                .password(passwordEncoder.encode(password))
                .email(email)
                .role(normalizedRole)
                .provider(Provider.LOCAL)
                .build();

        return userRepository.save(user);
    }

    /**
     * 사용자 조회 (username)
     */
    @Transactional(readOnly = true)
    public User findByUsername(String username) {
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new AuthException("User not found"));
    }

    /**
     * 사용자 조회 (ID)
     */
    @Transactional(readOnly = true)
    public User findById(Long id) {
        return userRepository.findById(id)
                .orElseThrow(() -> new AuthException("User not found"));
    }

    /**
     * 비밀번호 일치 확인
     */
    public boolean matchesPassword(String rawPassword, String encodedPassword) {
        return passwordEncoder.matches(rawPassword, encodedPassword);
    }

    /**
     * 비밀번호 암호화
     */
    public String encodePassword(String rawPassword) {
        return passwordEncoder.encode(rawPassword);
    }
}
