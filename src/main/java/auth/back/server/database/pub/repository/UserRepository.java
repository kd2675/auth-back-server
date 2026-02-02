package auth.back.server.database.pub.repository;

import auth.back.server.database.pub.entity.User;
import auth.common.core.constant.Provider;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);
    Optional<User> findByEmail(String email);
    Optional<User> findByProviderAndProviderId(Provider provider, String providerId);
    boolean existsByUsername(String username);
    boolean existsByEmail(String email);
}
