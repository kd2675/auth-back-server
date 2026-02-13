package auth.back.server.database.pub.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Lob;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Entity
@Table(name = "oauth2_authorization")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class OAuth2Authorization {

    @Id
    @Column(length = 100)
    private String id;

    @Column(name = "registered_client_id", length = 100, nullable = false)
    private String registeredClientId;

    @Column(name = "principal_name", length = 200, nullable = false)
    private String principalName;

    @Column(name = "authorization_grant_type", length = 100, nullable = false)
    private String authorizationGrantType;

    @Column(name = "authorized_scopes", length = 1000)
    private String authorizedScopes;

    @Lob
    @Column(name = "attributes", columnDefinition = "blob")
    private byte[] attributes;

    @Column(name = "state", length = 500)
    private String state;

    @Lob
    @Column(name = "authorization_code_value", columnDefinition = "blob")
    private byte[] authorizationCodeValue;

    @Column(name = "authorization_code_issued_at")
    private LocalDateTime authorizationCodeIssuedAt;

    @Column(name = "authorization_code_expires_at")
    private LocalDateTime authorizationCodeExpiresAt;

    @Lob
    @Column(name = "authorization_code_metadata", columnDefinition = "blob")
    private byte[] authorizationCodeMetadata;

    @Lob
    @Column(name = "access_token_value", columnDefinition = "blob")
    private byte[] accessTokenValue;

    @Column(name = "access_token_issued_at")
    private LocalDateTime accessTokenIssuedAt;

    @Column(name = "access_token_expires_at")
    private LocalDateTime accessTokenExpiresAt;

    @Lob
    @Column(name = "access_token_metadata", columnDefinition = "blob")
    private byte[] accessTokenMetadata;

    @Column(name = "access_token_type", length = 100)
    private String accessTokenType;

    @Column(name = "access_token_scopes", length = 1000)
    private String accessTokenScopes;

    @Lob
    @Column(name = "oidc_id_token_value", columnDefinition = "blob")
    private byte[] oidcIdTokenValue;

    @Column(name = "oidc_id_token_issued_at")
    private LocalDateTime oidcIdTokenIssuedAt;

    @Column(name = "oidc_id_token_expires_at")
    private LocalDateTime oidcIdTokenExpiresAt;

    @Lob
    @Column(name = "oidc_id_token_metadata", columnDefinition = "blob")
    private byte[] oidcIdTokenMetadata;

    @Lob
    @Column(name = "refresh_token_value", columnDefinition = "blob")
    private byte[] refreshTokenValue;

    @Column(name = "refresh_token_issued_at")
    private LocalDateTime refreshTokenIssuedAt;

    @Column(name = "refresh_token_expires_at")
    private LocalDateTime refreshTokenExpiresAt;

    @Lob
    @Column(name = "refresh_token_metadata", columnDefinition = "blob")
    private byte[] refreshTokenMetadata;
}
