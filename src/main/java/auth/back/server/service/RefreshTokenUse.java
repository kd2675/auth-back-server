package auth.back.server.service;

import auth.back.server.database.pub.entity.RefreshToken;

public record RefreshTokenUse(
        RefreshToken token,
        boolean concurrentRetry
) {
}
