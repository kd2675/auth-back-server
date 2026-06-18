package auth.back.server.service.oauth2;

import auth.back.server.database.pub.entity.User;
import auth.common.core.constant.UserRole;
import auth.common.core.exception.AuthException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class OAuth2ClientAuthorizationServiceTest {

    @Mock
    private RegisteredClientRepository registeredClientRepository;

    @Mock
    private OAuth2AuthorizationService authorizationService;

    @Mock
    private OAuth2AuthorizationConsentService authorizationConsentService;

    @Test
    void validateAndSaveAuthorization_stockSocialClient_resolvesStockFrontClient() {
        OAuth2ClientAuthorizationService service = service();
        RegisteredClient registeredClient = registeredClient("stock-front-service");
        when(registeredClientRepository.findByClientId("stock-front-service")).thenReturn(registeredClient);
        User user = User.builder()
                .userKey("stock-user")
                .username("stock")
                .email("stock@example.com")
                .role(UserRole.USER)
                .build();

        service.validateAndSaveAuthorization(
                "naver-stock",
                user,
                "access-token",
                Instant.parse("2026-06-17T00:00:00Z"),
                Instant.parse("2026-06-17T01:00:00Z"),
                "refresh-token",
                Instant.parse("2026-06-17T00:00:00Z"),
                Instant.parse("2026-06-24T00:00:00Z")
        );

        verify(registeredClientRepository).findByClientId("stock-front-service");
        ArgumentCaptor<OAuth2AuthorizationConsent> consentCaptor = ArgumentCaptor.forClass(OAuth2AuthorizationConsent.class);
        verify(authorizationConsentService).save(consentCaptor.capture());
        assertThat(consentCaptor.getValue().getRegisteredClientId()).isEqualTo("registered-stock-front-service");
        assertThat(consentCaptor.getValue().getPrincipalName()).isEqualTo("stock-user");

        ArgumentCaptor<OAuth2Authorization> authorizationCaptor = ArgumentCaptor.forClass(OAuth2Authorization.class);
        verify(authorizationService).save(authorizationCaptor.capture());
        assertThat(authorizationCaptor.getValue().getRegisteredClientId()).isEqualTo("registered-stock-front-service");
        assertThat(authorizationCaptor.getValue().getPrincipalName()).isEqualTo("stock-user");
        String originalClientId = authorizationCaptor.getValue().getAttribute("client_id");
        assertThat(originalClientId).isEqualTo("naver-stock");
    }

    @Test
    void validateAndSaveAuthorization_unknownSocialClient_throwsAuthException() {
        OAuth2ClientAuthorizationService service = service();
        User user = User.builder()
                .userKey("stock-user")
                .username("stock")
                .email("stock@example.com")
                .role(UserRole.USER)
                .build();

        assertThatThrownBy(() -> service.validateAndSaveAuthorization(
                "naver-unknown",
                user,
                "access-token",
                Instant.parse("2026-06-17T00:00:00Z"),
                Instant.parse("2026-06-17T01:00:00Z"),
                "refresh-token",
                Instant.parse("2026-06-17T00:00:00Z"),
                Instant.parse("2026-06-24T00:00:00Z")
        )).isInstanceOf(AuthException.class)
                .hasMessageContaining("Unknown client id");
    }

    @Test
    void validateRefreshClient_matchingFrontClient_doesNotThrow() {
        OAuth2ClientAuthorizationService service = service();
        RegisteredClient registeredClient = registeredClient("stock-front-service");
        when(registeredClientRepository.findByClientId("stock-front-service")).thenReturn(registeredClient);

        service.validateRefreshClient("stock-front-service", "registered-stock-front-service");

        verify(registeredClientRepository).findByClientId("stock-front-service");
    }

    @Test
    void validateRefreshClient_mismatchedFrontClient_throwsAuthException() {
        OAuth2ClientAuthorizationService service = service();
        RegisteredClient registeredClient = registeredClient("stock-front-service");
        when(registeredClientRepository.findByClientId("stock-front-service")).thenReturn(registeredClient);

        assertThatThrownBy(() -> service.validateRefreshClient("stock-front-service", "registered-semo-front-service"))
                .isInstanceOf(AuthException.class)
                .hasMessageContaining("Refresh token client mismatch");
    }

    private OAuth2ClientAuthorizationService service() {
        OAuth2ClientAuthorizationService service = new OAuth2ClientAuthorizationService(
                registeredClientRepository,
                authorizationService,
                authorizationConsentService
        );
        ReflectionTestUtils.setField(service, "museClientId", "muse-front-service");
        ReflectionTestUtils.setField(service, "zeroqServiceClientId", "zeroq-front-service");
        ReflectionTestUtils.setField(service, "zeroqAdminClientId", "zeroq-front-admin");
        ReflectionTestUtils.setField(service, "semoClientId", "semo-front-service");
        ReflectionTestUtils.setField(service, "stockClientId", "stock-front-service");
        return service;
    }

    private RegisteredClient registeredClient(String clientId) {
        return RegisteredClient.withId("registered-" + clientId)
                .clientId(clientId)
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("http://localhost:3005/login/oauth2/code/stock-front-service")
                .scope("openid")
                .scope("profile")
                .build();
    }
}
