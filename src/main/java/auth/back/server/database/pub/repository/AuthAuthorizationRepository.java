package auth.back.server.database.pub.repository;

import auth.back.server.database.pub.entity.AuthAuthorization;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface AuthAuthorizationRepository extends JpaRepository<AuthAuthorization, String> {

    Optional<AuthAuthorization> findByRefreshTokenHash(String refreshTokenHash);

    Optional<AuthAuthorization> findByAccessTokenHash(String accessTokenHash);

    List<AuthAuthorization> findByPrincipalNameAndInvalidatedFalse(String principalName);
}
