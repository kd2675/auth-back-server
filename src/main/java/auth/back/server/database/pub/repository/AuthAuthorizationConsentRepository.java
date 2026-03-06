package auth.back.server.database.pub.repository;

import auth.back.server.database.pub.entity.AuthAuthorizationConsent;
import auth.back.server.database.pub.entity.AuthAuthorizationConsentId;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface AuthAuthorizationConsentRepository
        extends JpaRepository<AuthAuthorizationConsent, AuthAuthorizationConsentId> {
}
