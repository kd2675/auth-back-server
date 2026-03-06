package auth.back.server.database.pub.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "auth_registered_client")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AuthRegisteredClient {

    @Id
    @Column(length = 100)
    private String id;

    @Column(name = "client_id", length = 100, nullable = false)
    private String clientId;

    @Column(name = "client_name", length = 200, nullable = false)
    private String clientName;

    @Column(name = "scopes", length = 1000, nullable = false)
    private String scopes;

    @Column(name = "access_token_ttl_seconds", nullable = false)
    private Integer accessTokenTtlSeconds;

    @Column(name = "refresh_token_ttl_seconds", nullable = false)
    private Integer refreshTokenTtlSeconds;

    @Column(name = "require_consent", nullable = false)
    private Boolean requireConsent;

    @Column(name = "enabled", nullable = false)
    private Boolean enabled;
}
