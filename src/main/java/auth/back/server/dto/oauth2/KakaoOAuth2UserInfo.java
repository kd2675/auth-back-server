package auth.back.server.dto.oauth2;

import java.util.Map;

public class KakaoOAuth2UserInfo extends OAuth2UserInfo {

    public KakaoOAuth2UserInfo(Map<String, Object> attributes) {
        super(attributes);
    }

    @Override
    public String getId() {
        Object id = attributes.get("id");
        return id == null ? null : String.valueOf(id);
    }

    @Override
    public String getName() {
        Map<String, Object> properties = getMap(attributes.get("properties"));
        if (properties != null) {
            Object nickname = properties.get("nickname");
            if (nickname instanceof String) {
                return (String) nickname;
            }
        }

        Map<String, Object> kakaoAccount = getMap(attributes.get("kakao_account"));
        if (kakaoAccount != null) {
            Map<String, Object> profile = getMap(kakaoAccount.get("profile"));
            if (profile != null) {
                Object nickname = profile.get("nickname");
                if (nickname instanceof String) {
                    return (String) nickname;
                }
            }
        }

        return null;
    }

    @Override
    public String getEmail() {
        Map<String, Object> kakaoAccount = getMap(attributes.get("kakao_account"));
        if (kakaoAccount == null) {
            return null;
        }

        Object email = kakaoAccount.get("email");
        if (email instanceof String) {
            return (String) email;
        }

        return null;
    }

    @Override
    public String getImageUrl() {
        Map<String, Object> properties = getMap(attributes.get("properties"));
        if (properties != null) {
            Object profileImage = properties.get("profile_image");
            if (profileImage instanceof String) {
                return (String) profileImage;
            }
        }

        Map<String, Object> kakaoAccount = getMap(attributes.get("kakao_account"));
        if (kakaoAccount != null) {
            Map<String, Object> profile = getMap(kakaoAccount.get("profile"));
            if (profile != null) {
                Object profileImage = profile.get("profile_image_url");
                if (profileImage instanceof String) {
                    return (String) profileImage;
                }
            }
        }

        return null;
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> getMap(Object value) {
        if (value instanceof Map) {
            return (Map<String, Object>) value;
        }
        return null;
    }
}
