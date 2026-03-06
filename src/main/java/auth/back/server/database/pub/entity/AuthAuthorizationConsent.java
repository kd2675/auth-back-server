package auth.back.server.database.pub.entity;

import jakarta.persistence.Column;
import jakarta.persistence.EmbeddedId;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "auth_authorization_consent")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AuthAuthorizationConsent {

    @EmbeddedId
    private AuthAuthorizationConsentId id;

    @Column(name = "authorities", length = 1000, nullable = false)
    private String authorities;
}
