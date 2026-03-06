package auth.back.server.service;

import auth.back.server.database.pub.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.UUID;

@Component
@RequiredArgsConstructor
public class UserKeyGenerator {

    private static final String PREFIX = "user_";
    private static final int MAX_RETRIES = 20;

    private final UserRepository userRepository;

    public String nextUserKey() {
        for (int attempt = 0; attempt < MAX_RETRIES; attempt++) {
            String candidate = generateCandidate();
            if (!userRepository.existsByUserKey(candidate)) {
                return candidate;
            }
        }
        throw new IllegalStateException("Failed to generate unique user_key");
    }

    private String generateCandidate() {
        return PREFIX + UUID.randomUUID();
    }
}
