package auth.back.server.dto.oauth2;

import java.util.Map;

public class KakaoOAuth2UserInfo extends OAuth2UserInfo {

    public KakaoOAuth2UserInfo(Map<String, Object> attributes) {
        super(attributes);
    }

    @Override
    public String getId() {
        Object id = attributes.get("id");
        if (id == null) {
            return null;
        }
        return String.valueOf(id);
    }

    @Override
    public String getName() {
        Map<String, Object> properties = getMap(attributes, "properties");
        if (properties == null) {
            return null;
        }
        return asString(properties.get("nickname"));
    }

    @Override
    public String getEmail() {
        Map<String, Object> kakaoAccount = getMap(attributes, "kakao_account");
        if (kakaoAccount == null) {
            return null;
        }
        return asString(kakaoAccount.get("email"));
    }

    @Override
    public String getImageUrl() {
        Map<String, Object> properties = getMap(attributes, "properties");
        if (properties == null) {
            return null;
        }
        return asString(properties.get("profile_image"));
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> getMap(Map<String, Object> source, String key) {
        Object value = source.get(key);
        if (value instanceof Map<?, ?> map) {
            return (Map<String, Object>) map;
        }
        return null;
    }

    private String asString(Object value) {
        return value == null ? null : String.valueOf(value);
    }
}
