package auth.back.server.service;

import auth.back.server.database.pub.entity.User;
import auth.back.server.database.pub.repository.UserRepository;
import auth.common.core.constant.UserRole;
import auth.common.core.exception.AuthException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class UserServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private UserKeyGenerator userKeyGenerator;

    @InjectMocks
    private UserService userService;

    @Test
    void registerUser_nullRole_savesUserRole() {
        when(userRepository.existsByUsername("user")).thenReturn(false);
        when(userRepository.existsByEmail("user@example.com")).thenReturn(false);
        when(userKeyGenerator.nextUserKey()).thenReturn("user-key");
        when(passwordEncoder.encode("password")).thenReturn("encoded-password");
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));

        User result = userService.registerUser("user", "password", "user@example.com", null, null);

        ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
        assertThat(result.getRole()).isEqualTo(UserRole.USER);
        verify(userRepository).save(userCaptor.capture());
        assertThat(userCaptor.getValue().getRole()).isEqualTo(UserRole.USER);
    }

    @Test
    void registerUser_gatewayRole_throwsAuthException() {
        when(userRepository.existsByUsername("gateway")).thenReturn(false);
        when(userRepository.existsByEmail("gateway@example.com")).thenReturn(false);

        assertThatThrownBy(() -> userService.registerUser(
                "gateway",
                "password",
                "gateway@example.com",
                "ROLE_GATEWAY",
                null
        )).isInstanceOf(AuthException.class)
                .hasMessage("Invalid role. Allowed: USER, MANAGER");

        verify(userRepository, never()).save(any(User.class));
    }
}
