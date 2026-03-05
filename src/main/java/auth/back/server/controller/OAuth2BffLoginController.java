package auth.back.server.controller;

import auth.back.server.service.oauth2.OAuth2LoginChannelService;
import auth.common.core.exception.AuthException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.Locale;
import java.util.regex.Pattern;

@Controller
@RequestMapping("/auth/bff/login")
@RequiredArgsConstructor
public class OAuth2BffLoginController {
    private static final String DEFAULT_PROVIDER = "naver";
    private static final Pattern PROVIDER_KEY_PATTERN = Pattern.compile("^[a-z0-9-]+$");

    private final OAuth2LoginChannelService oauth2LoginChannelService;

    @GetMapping("/{channel}")
    public String loginByChannel(
            @PathVariable String channel,
            @RequestParam(value = "provider", required = false) String provider
    ) {
        oauth2LoginChannelService.rememberChannel(channel);
        return "redirect:/oauth2/authorization/" + normalizeProvider(provider);
    }

    private String normalizeProvider(String provider) {
        if (provider == null || provider.isBlank()) {
            return DEFAULT_PROVIDER;
        }

        String normalized = provider.trim().toLowerCase(Locale.ROOT);
        if (!PROVIDER_KEY_PATTERN.matcher(normalized).matches()) {
            throw new AuthException("Unsupported oauth2 provider: " + provider);
        }
        return normalized;
    }
}

