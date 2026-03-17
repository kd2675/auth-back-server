package auth.back.server.service.oauth2;

import auth.back.server.database.pub.entity.User;
import auth.back.server.database.pub.repository.UserRepository;
import auth.back.server.dto.oauth2.OAuth2UserInfo;
import auth.back.server.dto.oauth2.OAuth2UserInfoFactory;
import auth.back.server.service.UserKeyGenerator;
import auth.common.core.constant.Provider;
import auth.common.core.constant.UserRole;
import auth.common.core.exception.OAuth2AuthenticationProcessingException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;
    private final UserKeyGenerator userKeyGenerator;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest oAuth2UserRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(oAuth2UserRequest);

        try {
            return processOAuth2User(oAuth2UserRequest, oAuth2User);
        } catch (AuthenticationException ex) {
            throw ex;
        } catch (Exception ex) {
            // Throwing an instance of AuthenticationException will trigger the OAuth2AuthenticationFailureHandler
            throw new InternalAuthenticationServiceException(ex.getMessage(), ex);
        }
    }

    private OAuth2User processOAuth2User(OAuth2UserRequest oAuth2UserRequest, OAuth2User oAuth2User) {
        String clientId = oAuth2UserRequest.getClientRegistration().getRegistrationId();
        OAuth2UserInfo oAuth2UserInfo = OAuth2UserInfoFactory.getOAuth2UserInfo(clientId, oAuth2User.getAttributes());

        User user = resolveOrRegisterUser(clientId, oAuth2UserInfo);

        return new UserPrincipal(user, oAuth2User.getAttributes());
    }

    User resolveOrRegisterUser(String clientId, OAuth2UserInfo oAuth2UserInfo) {
        if (!StringUtils.hasText(oAuth2UserInfo.getEmail())) {
            throw new OAuth2AuthenticationProcessingException(
                    "Email not found from OAuth2 provider",
                    "oauth_email_missing",
                    null
            );
        }

        Provider provider = resolveProvider(clientId);

        Optional<User> exactMatch = userRepository.findByProviderAndProviderId(provider, oAuth2UserInfo.getId());
        if (exactMatch.isPresent()) {
            return updateExistingUser(exactMatch.get(), oAuth2UserInfo, provider);
        }

        Optional<User> emailMatch = userRepository.findByEmail(oAuth2UserInfo.getEmail());
        if (emailMatch.isPresent()) {
            User existingUser = emailMatch.get();
            if (!existingUser.getProvider().equals(provider)) {
                throw new OAuth2AuthenticationProcessingException("Looks like you're signed up with " +
                        existingUser.getProvider() + " account. Please use your " + existingUser.getProvider() +
                        " account to login.",
                        "oauth_provider_mismatch",
                        existingUser.getProvider().name());
            }
            return updateExistingUser(existingUser, oAuth2UserInfo, provider);
        }

        return registerNewUser(provider, oAuth2UserInfo);
    }

    private User registerNewUser(Provider provider, OAuth2UserInfo oAuth2UserInfo) {
        User user = User.builder()
                .userKey(userKeyGenerator.nextUserKey())
                .username(oAuth2UserInfo.getName())
                .email(oAuth2UserInfo.getEmail())
                .imageUrl(oAuth2UserInfo.getImageUrl())
                .provider(provider)
                .providerId(oAuth2UserInfo.getId())
                .role(UserRole.USER)
                .build();
        return userRepository.save(user);
    }

    private User updateExistingUser(User existingUser, OAuth2UserInfo oAuth2UserInfo, Provider provider) {
        existingUser.setUsername(oAuth2UserInfo.getName());
        existingUser.setEmail(oAuth2UserInfo.getEmail());
        existingUser.setImageUrl(oAuth2UserInfo.getImageUrl());
        existingUser.setProvider(provider);
        existingUser.setProviderId(oAuth2UserInfo.getId());
        return userRepository.save(existingUser);
    }

    private Provider resolveProvider(String clientId) {
        String normalized = clientId == null ? "" : clientId.trim().toLowerCase();

        if (normalized.startsWith(Provider.NAVER.name().toLowerCase())) {
            return Provider.NAVER;
        }
        if (normalized.startsWith(Provider.KAKAO.name().toLowerCase())) {
            return Provider.KAKAO;
        }

        throw new OAuth2AuthenticationProcessingException(
                "Unsupported OAuth2 provider: " + clientId,
                "oauth_provider_unsupported",
                null
        );
    }
}
