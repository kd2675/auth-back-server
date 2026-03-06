package auth.back.server.dto.oauth2;

import auth.common.core.constant.Provider;
import auth.common.core.exception.OAuth2AuthenticationProcessingException;

import java.util.Map;

public class OAuth2UserInfoFactory {

    public static OAuth2UserInfo getOAuth2UserInfo(String clientId, Map<String, Object> attributes) {
        String normalized = clientId == null ? "" : clientId.trim().toLowerCase();

        if (normalized.startsWith(Provider.NAVER.name().toLowerCase())) {
            return new NaverOAuth2UserInfo(attributes);
        } else if (normalized.startsWith(Provider.KAKAO.name().toLowerCase())) {
            return new KakaoOAuth2UserInfo(attributes);
        } else {
            throw new OAuth2AuthenticationProcessingException("Login with " + clientId + " is not supported yet.");
        }
    }
}
