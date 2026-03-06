package auth.back.server.service;

import auth.back.server.database.pub.entity.AuthRegisteredClient;
import auth.back.server.database.pub.repository.AuthRegisteredClientRepository;
import auth.common.core.exception.AuthException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class AuthRegisteredClientService {

    private final AuthRegisteredClientRepository authRegisteredClientRepository;

    public AuthRegisteredClient validateActiveClient(String clientIdHeader) {
        if (!StringUtils.hasText(clientIdHeader)) {
            throw new AuthException("X-Client-Id header is required");
        }

        String clientId = clientIdHeader.trim();
        return authRegisteredClientRepository.findByClientIdAndEnabledTrue(clientId)
                .orElseThrow(() -> new AuthException("Invalid or disabled client: " + clientId));
    }
}
