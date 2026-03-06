package auth.back.server.controller;

import auth.back.server.database.pub.entity.User;
import auth.back.server.database.pub.repository.UserRepository;
import auth.back.server.service.UserService;
import auth.common.core.constant.UserRole;
import auth.common.core.dto.UserCreateRequest;
import auth.common.core.dto.UserDto;
import auth.common.core.dto.UserUpdateRequest;
import auth.common.core.exception.AuthException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import web.common.core.response.base.dto.ResponseDataDTO;

import java.util.List;
import java.util.stream.Collectors;

/**
 * User Controller - 사용자 정보 관리 전용 컨트롤러
 *
 * Gateway Offloading 패턴:
 * - JWT 검증은 Gateway(cloud-back-server)에서 수행
 * - Gateway가 X-User-Key, X-User-Role 헤더를 추가해서 보냄
 * - 이 컨트롤러는 헤더 정보를 신뢰하고 비즈니스 로직만 수행
 *
 * 엔드포인트:
 * - GET    /api/users                : 모든 사용자 조회 (ADMIN만)
 * - GET    /api/users/{userKey}       : user_key(opaque)로 사용자 조회
 * - GET    /api/users/username/{username} : Username으로 조회
 * - GET    /api/users/email/{email}       : Email로 조회
 * - GET    /api/users/{userKey}/exists     : 사용자 존재 여부 확인
 * - POST   /api/users                : 사용자 생성 (회원가입)
 * - PUT    /api/users/{userKey}       : 사용자 정보 수정
 * - DELETE /api/users/{userKey}       : 사용자 삭제
 */
@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
@Slf4j
public class UserController {

    private final UserRepository userRepository;
    private final UserService userService;

    /**
     * 본인 정보 조회
     * GET /api/users/me
     * - Gateway가 보내준 X-User-Key 헤더를 사용하여 본인 정보 조회
     */
    @GetMapping("/me")
    public ResponseDataDTO<UserDto> getMyInfo(
            @RequestHeader(value = "X-User-Key", required = false) String userKeyHeader) {
        log.info("Get my info: userKey={}", userKeyHeader);

        if (userKeyHeader == null || userKeyHeader.isEmpty()) {
            throw new AuthException("Authentication required");
        }

        User user = userService.findByUserKey(userKeyHeader);
        return ResponseDataDTO.of(convertToDto(user));
    }

    /**
     * user_key로 User 조회 (본인 또는 ADMIN만 가능)
     * GET /api/users/{userKey}
     * - Gateway가 보내준 X-User-Key, X-User-Role 헤더로 권한 확인
     */
    @GetMapping("/{userKey}")
    public ResponseDataDTO<UserDto> getUserByUserKey(
            @PathVariable String userKey,
            @RequestHeader(value = "X-User-Key", required = false) String userKeyHeader,
            @RequestHeader(value = "X-User-Role", required = false) String userRole) {
        log.info("Get user by id: userKey={}, requester={}", userKey, userKeyHeader);

        checkPermission(userKey, userKeyHeader, userRole);

        User user = userService.findByUserKey(userKey);
        return ResponseDataDTO.of(convertToDto(user));
    }

    /**
     * Username으로 User 조회 (내부 서비스용 또는 본인/ADMIN)
     * GET /api/users/username/{username}
     */
    @GetMapping("/username/{username}")
    public ResponseDataDTO<UserDto> getUserByUsername(
            @PathVariable String username,
            @RequestHeader(value = "X-User-Key", required = false) String userKeyHeader,
            @RequestHeader(value = "X-User-Role", required = false) String userRole) {
        log.info("Get user by username: username={}, requester={}", username, userKeyHeader);

        User user = userService.findByUsername(username);

        if (userKeyHeader != null && !userKeyHeader.isEmpty()) {
            checkPermission(user.getUserKey(), userKeyHeader, userRole);
        }

        return ResponseDataDTO.of(convertToDto(user));
    }

    /**
     * Email로 User 조회 (내부 서비스용 또는 본인/ADMIN)
     * GET /api/users/email/{email}
     */
    @GetMapping("/email/{email}")
    public ResponseDataDTO<UserDto> getUserByEmail(
            @PathVariable String email,
            @RequestHeader(value = "X-User-Key", required = false) String userKeyHeader,
            @RequestHeader(value = "X-User-Role", required = false) String userRole) {
        log.info("Get user by email: email={}, requester={}", email, userKeyHeader);

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new AuthException("User not found with email: " + email));

        if (userKeyHeader != null && !userKeyHeader.isEmpty()) {
            checkPermission(user.getUserKey(), userKeyHeader, userRole);
        }

        return ResponseDataDTO.of(convertToDto(user));
    }

    /**
     * 모든 User 조회 (ADMIN만 가능)
     * GET /api/users
     */
    @GetMapping
    public ResponseDataDTO<List<UserDto>> getAllUsers(
            @RequestHeader(value = "X-User-Role", required = false) String userRole) {
        log.info("Get all users, role: {}", userRole);

        if (!isAdmin(userRole)) {
            throw new AuthException("Admin access required");
        }

        List<User> users = userRepository.findAll();
        List<UserDto> userDtos = users.stream()
                .map(this::convertToDto)
                .collect(Collectors.toList());
        return ResponseDataDTO.of(userDtos);
    }

    /**
     * User 생성 (회원가입)
     * POST /api/users
     */
    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public ResponseDataDTO<UserDto> createUser(@RequestBody UserCreateRequest request) {
        log.info(
                "Create user: username={}, email={}, role={}",
                request.getUsername(),
                request.getEmail(),
                request.getRole()
        );
        User user = userService.registerUser(
                request.getUsername(),
                request.getPassword(),
                request.getEmail(),
                request.getRole(),
                request.getSignupSecret()
        );
        return ResponseDataDTO.of(convertToDto(user), "User created successfully");
    }

    /**
     * User 수정 (본인 또는 ADMIN만 가능)
     * PUT /api/users/{userKey}
     */
    @PutMapping("/{userKey}")
    public ResponseDataDTO<UserDto> updateUser(
            @PathVariable String userKey,
            @RequestBody UserUpdateRequest request,
            @RequestHeader(value = "X-User-Key", required = false) String userKeyHeader,
            @RequestHeader(value = "X-User-Role", required = false) String userRole) {
        log.info("Update user: userKey={}, requester={}", userKey, userKeyHeader);

        checkPermission(userKey, userKeyHeader, userRole);

        User user = userService.findByUserKey(userKey);

        if (request.getEmail() != null) {
            user.setEmail(request.getEmail());
        }

        if (request.getRole() != null) {
            if (!isAdmin(userRole)) {
                throw new AuthException("Only admin can change user role");
            }
            if (!UserRole.isValidRole(request.getRole())) {
                throw new AuthException("Invalid role. Allowed: USER, MANAGER, ADMIN");
            }
            user.setRole(UserRole.normalize(request.getRole()));
        }

        if (request.getPassword() != null) {
            user.setPassword(userService.encodePassword(request.getPassword()));
        }

        User updatedUser = userRepository.save(user);
        return ResponseDataDTO.of(convertToDto(updatedUser), "User updated successfully");
    }

    /**
     * User 삭제 (본인 또는 ADMIN만 가능)
     * DELETE /api/users/{userKey}
     */
    @DeleteMapping("/{userKey}")
    public ResponseDataDTO<Void> deleteUser(
            @PathVariable String userKey,
            @RequestHeader(value = "X-User-Key", required = false) String userKeyHeader,
            @RequestHeader(value = "X-User-Role", required = false) String userRole) {
        log.info("Delete user: userKey={}, requester={}", userKey, userKeyHeader);

        checkPermission(userKey, userKeyHeader, userRole);

        User user = userService.findByUserKey(userKey);
        userRepository.delete(user);

        return ResponseDataDTO.of(null, "User deleted successfully");
    }

    /**
     * User 존재 여부 확인
     * GET /api/users/{userKey}/exists
     */
    @GetMapping("/{userKey}/exists")
    public ResponseDataDTO<Boolean> existsByUserKey(@PathVariable String userKey) {
        log.info("Check user existence: userKey={}", userKey);
        boolean exists = userRepository.existsByUserKey(userKey);
        return ResponseDataDTO.of(exists);
    }

    private UserDto convertToDto(User user) {
        return UserDto.builder()
                .userKey(user.getUserKey())
                .username(user.getUsername())
                .email(user.getEmail())
                .role(user.getRole())
                .createdAt(user.getCreatedAt())
                .updatedAt(user.getUpdatedAt())
                .build();
    }

    /**
     * 권한 체크: 본인 또는 ADMIN만 허용
     */
    private void checkPermission(String targetUserKey, String userKeyHeader, String userRole) {
        if (isAdmin(userRole)) {
            return;
        }

        if (userKeyHeader == null || userKeyHeader.isEmpty()) {
            throw new AuthException("Authentication required");
        }

        if (!userKeyHeader.equals(targetUserKey)) {
            throw new AuthException("You can only modify your own information");
        }
    }

    private boolean isAdmin(String userRole) {
        return UserRole.isAdmin(userRole);
    }
}
