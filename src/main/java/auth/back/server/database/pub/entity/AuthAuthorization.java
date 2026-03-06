package auth.back.server.database.pub.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Lob;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Entity
@Table(name = "auth_authorization")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AuthAuthorization {

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

    @Column(name = "access_token_hash", length = 64, nullable = false)
    private String accessTokenHash;

    @Lob
    @Column(name = "access_token_value", columnDefinition = "blob", nullable = false)
    private byte[] accessTokenValue;

    @Column(name = "access_token_issued_at", nullable = false)
    private LocalDateTime accessTokenIssuedAt;

    @Column(name = "access_token_expires_at", nullable = false)
    private LocalDateTime accessTokenExpiresAt;

    @Column(name = "refresh_token_hash", length = 64, nullable = false)
    private String refreshTokenHash;

    @Lob
    @Column(name = "refresh_token_value", columnDefinition = "blob", nullable = false)
    private byte[] refreshTokenValue;

    @Column(name = "refresh_token_issued_at", nullable = false)
    private LocalDateTime refreshTokenIssuedAt;

    @Column(name = "refresh_token_expires_at", nullable = false)
    private LocalDateTime refreshTokenExpiresAt;

    @Column(name = "invalidated", nullable = false)
    private Boolean invalidated;

    @Column(name = "invalidated_at")
    private LocalDateTime invalidatedAt;

    @Column(name = "invalidation_reason", length = 255)
    private String invalidationReason;

    @PrePersist
    protected void onCreate() {
        if (invalidated == null) {
            invalidated = false;
        }
    }
}
