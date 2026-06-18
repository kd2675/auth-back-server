package auth.back.server.controller;

import auth.back.server.database.pub.entity.User;
import auth.back.server.database.pub.repository.UserRepository;
import auth.back.server.service.JwtTokenProvider;
import auth.common.core.constant.Provider;
import auth.common.core.constant.UserRole;
import jakarta.servlet.Filter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import static org.hamcrest.Matchers.nullValue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@ActiveProfiles("test")
class UserControllerSecurityIntegrationTest {

    private MockMvc mockMvc;

    @Autowired
    private WebApplicationContext webApplicationContext;

    @Autowired
    @Qualifier("springSecurityFilterChain")
    private Filter springSecurityFilterChain;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext)
                .addFilters(springSecurityFilterChain)
                .build();
        userRepository.deleteAll();
    }

    @Test
    void createUser_withoutBearerToken_returnsCreated() throws Exception {
        mockMvc.perform(post("/api/users")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "username": "stock-user",
                                  "password": "stock-password",
                                  "email": "stock-user@example.com"
                                }
                                """))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data.username").value("stock-user"))
                .andExpect(jsonPath("$.data.role").value(UserRole.USER));
    }

    @Test
    void getMyInfo_withoutBearerToken_returnsUnauthorizedJsonNotLoginRedirect() throws Exception {
        mockMvc.perform(get("/api/users/me"))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string("Location", nullValue()))
                .andExpect(jsonPath("$.success").value(false))
                .andExpect(jsonPath("$.code").value(401))
                .andExpect(jsonPath("$.message").value("Unauthorized"));
    }

    @Test
    void getMyInfo_withBearerTokenAndGatewayUserHeader_returnsCurrentUser() throws Exception {
        User user = userRepository.save(User.builder()
                .userKey("stock-user-key")
                .username("stock-current-user")
                .password(passwordEncoder.encode("stock-password"))
                .email("stock-current-user@example.com")
                .role(UserRole.USER)
                .provider(Provider.LOCAL)
                .build());
        String accessToken = jwtTokenProvider.generateAccessToken(user, "local", "stock-front-service");

        mockMvc.perform(get("/api/users/me")
                        .header("Authorization", "Bearer " + accessToken)
                        .header("X-User-Key", user.getUserKey()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data.userKey").value(user.getUserKey()))
                .andExpect(jsonPath("$.data.username").value(user.getUsername()))
                .andExpect(jsonPath("$.data.role").value(UserRole.USER));
    }
}
