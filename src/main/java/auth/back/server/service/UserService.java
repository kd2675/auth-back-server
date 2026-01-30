package auth.back.server.service;

import auth.back.server.database.pub.entity.User;
import auth.back.server.database.pub.repository.UserRepository;
import auth.common.core.exception.AuthException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Transactional
@Slf4j
public class UserService implements UserDetailsService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

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
        if (userRepository.existsByUsername(username)) {
            throw new AuthException("Username already exists");
        }
        if (userRepository.existsByEmail(email)) {
            throw new AuthException("Email already exists");
        }

        User user = User.builder()
                .username(username)
                .password(passwordEncoder.encode(password))
                .email(email)
                .role("USER")
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
