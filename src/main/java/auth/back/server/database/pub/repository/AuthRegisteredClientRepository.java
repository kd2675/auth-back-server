package auth.back.server.database.pub.repository;

import auth.back.server.database.pub.entity.AuthRegisteredClient;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface AuthRegisteredClientRepository extends JpaRepository<AuthRegisteredClient, String> {

    Optional<AuthRegisteredClient> findByClientId(String clientId);

    Optional<AuthRegisteredClient> findByClientIdAndEnabledTrue(String clientId);
}
