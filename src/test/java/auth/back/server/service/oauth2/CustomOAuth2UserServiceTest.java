package auth.back.server.service.oauth2;

import auth.back.server.database.pub.entity.User;
import auth.back.server.database.pub.repository.UserRepository;
import auth.back.server.dto.oauth2.OAuth2UserInfo;
import auth.back.server.service.UserKeyGenerator;
import auth.common.core.constant.Provider;
import auth.common.core.constant.UserRole;
import auth.common.core.exception.OAuth2AuthenticationProcessingException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CustomOAuth2UserServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private UserKeyGenerator userKeyGenerator;

    @InjectMocks
    private CustomOAuth2UserService customOAuth2UserService;

    @Test
    void shouldRejectLoginWhenEmailBelongsToDifferentProvider() {
        OAuth2UserInfo userInfo = mockUserInfo("provider-id", "same@example.com", "Kakao User", "image");
        User existingUser = User.builder()
                .userKey("user-key")
                .username("Naver User")
                .email("same@example.com")
                .provider(Provider.NAVER)
                .providerId("naver-id")
                .role(UserRole.USER)
                .build();

        when(userRepository.findByProviderAndProviderId(Provider.KAKAO, "provider-id"))
                .thenReturn(Optional.empty());
        when(userRepository.findByEmail("same@example.com")).thenReturn(Optional.of(existingUser));

        assertThatThrownBy(() -> customOAuth2UserService.resolveOrRegisterUser("kakao-semo", userInfo))
                .isInstanceOf(OAuth2AuthenticationProcessingException.class)
                .hasMessageContaining("NAVER");

        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    void shouldReuseSameProviderUserFoundByEmail() {
        OAuth2UserInfo userInfo = mockUserInfo("new-provider-id", "same@example.com", "Updated Name", "new-image");
        User existingUser = User.builder()
                .userKey("user-key")
                .username("Old Name")
                .email("same@example.com")
                .provider(Provider.KAKAO)
                .providerId(null)
                .role(UserRole.USER)
                .build();

        when(userRepository.findByProviderAndProviderId(Provider.KAKAO, "new-provider-id"))
                .thenReturn(Optional.empty());
        when(userRepository.findByEmail("same@example.com")).thenReturn(Optional.of(existingUser));
        when(userRepository.save(existingUser)).thenReturn(existingUser);

        User result = customOAuth2UserService.resolveOrRegisterUser("kakao-semo", userInfo);

        assertThat(result.getProvider()).isEqualTo(Provider.KAKAO);
        assertThat(result.getProviderId()).isEqualTo("new-provider-id");
        assertThat(result.getUsername()).isEqualTo("Updated Name");
        assertThat(result.getImageUrl()).isEqualTo("new-image");
    }

    @Test
    void shouldRegisterNewUserWhenNoExistingUserMatches() {
        OAuth2UserInfo userInfo = mockUserInfo("provider-id", "new@example.com", "New User", "image");

        when(userRepository.findByProviderAndProviderId(Provider.KAKAO, "provider-id"))
                .thenReturn(Optional.empty());
        when(userRepository.findByEmail("new@example.com")).thenReturn(Optional.empty());
        when(userKeyGenerator.nextUserKey()).thenReturn("generated-key");
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));

        User result = customOAuth2UserService.resolveOrRegisterUser("kakao-semo", userInfo);

        assertThat(result.getUserKey()).isEqualTo("generated-key");
        assertThat(result.getEmail()).isEqualTo("new@example.com");
        assertThat(result.getProvider()).isEqualTo(Provider.KAKAO);
        assertThat(result.getProviderId()).isEqualTo("provider-id");
        assertThat(result.getRole()).isEqualTo(UserRole.USER);
    }

    private OAuth2UserInfo mockUserInfo(String id, String email, String name, String imageUrl) {
        OAuth2UserInfo userInfo = mock(OAuth2UserInfo.class);
        when(userInfo.getId()).thenReturn(id);
        when(userInfo.getEmail()).thenReturn(email);
        lenient().when(userInfo.getName()).thenReturn(name);
        lenient().when(userInfo.getImageUrl()).thenReturn(imageUrl);
        return userInfo;
    }
}
