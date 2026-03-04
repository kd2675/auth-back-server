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
 * - Gateway가 X-User-Id, X-User-Role 헤더를 추가해서 보냄
 * - 이 컨트롤러는 헤더 정보를 신뢰하고 비즈니스 로직만 수행
 *
 * 엔드포인트:
 * - GET    /api/users              : 모든 사용자 조회 (ADMIN만)
 * - GET    /api/users/{id}         : ID로 사용자 조회
 * - GET    /api/users/username/{username} : Username으로 조회
 * - GET    /api/users/email/{email}       : Email로 조회
 * - GET    /api/users/{id}/exists  : 사용자 존재 여부 확인
 * - POST   /api/users              : 사용자 생성 (회원가입)
 * - PUT    /api/users/{id}         : 사용자 정보 수정
 * - DELETE /api/users/{id}         : 사용자 삭제
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
     * - Gateway가 보내준 X-User-Id 헤더를 사용하여 본인 정보 조회
     */
    @GetMapping("/me")
    public ResponseDataDTO<UserDto> getMyInfo(
            @RequestHeader(value = "X-User-Id", required = false) String userIdHeader) {
        log.info("Get my info: userId={}", userIdHeader);

        if (userIdHeader == null || userIdHeader.isEmpty()) {
            throw new AuthException("Authentication required");
        }

        Long userId = Long.parseLong(userIdHeader);
        User user = userService.findById(userId);
        return ResponseDataDTO.of(convertToDto(user));
    }

    /**
     * ID로 User 조회 (본인 또는 ADMIN만 가능)
     * GET /api/users/{id}
     * - Gateway가 보내준 X-User-Id, X-User-Role 헤더로 권한 확인
     */
    @GetMapping("/{id}")
    public ResponseDataDTO<UserDto> getUserById(
            @PathVariable Long id,
            @RequestHeader(value = "X-User-Id", required = false) String userIdHeader,
            @RequestHeader(value = "X-User-Role", required = false) String userRole) {
        log.info("Get user by id: id={}, requester={}", id, userIdHeader);

        // 권한 체크: 본인이거나 ADMIN이어야 함
        checkPermission(id, userIdHeader, userRole);

        User user = userService.findById(id);
        return ResponseDataDTO.of(convertToDto(user));
    }

    /**
     * Username으로 User 조회 (내부 서비스용 또는 본인/ADMIN)
     * GET /api/users/username/{username}
     * - 주로 내부 서비스에서 사용 (OpenFeign)
     * - 외부에서 접근 시 권한 체크
     */
    @GetMapping("/username/{username}")
    public ResponseDataDTO<UserDto> getUserByUsername(
            @PathVariable String username,
            @RequestHeader(value = "X-User-Id", required = false) String userIdHeader,
            @RequestHeader(value = "X-User-Role", required = false) String userRole) {
        log.info("Get user by username: username={}, requester={}", username, userIdHeader);

        User user = userService.findByUsername(username);

        // 외부 요청인 경우 (헤더가 있는 경우) 권한 체크
        if (userIdHeader != null && !userIdHeader.isEmpty()) {
            checkPermission(user.getId(), userIdHeader, userRole);
        }

        return ResponseDataDTO.of(convertToDto(user));
    }

    /**
     * Email로 User 조회 (내부 서비스용 또는 본인/ADMIN)
     * GET /api/users/email/{email}
     * - 주로 내부 서비스에서 사용 (OpenFeign)
     * - 외부에서 접근 시 권한 체크
     */
    @GetMapping("/email/{email}")
    public ResponseDataDTO<UserDto> getUserByEmail(
            @PathVariable String email,
            @RequestHeader(value = "X-User-Id", required = false) String userIdHeader,
            @RequestHeader(value = "X-User-Role", required = false) String userRole) {
        log.info("Get user by email: email={}, requester={}", email, userIdHeader);

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new AuthException("User not found with email: " + email));

        // 외부 요청인 경우 (헤더가 있는 경우) 권한 체크
        if (userIdHeader != null && !userIdHeader.isEmpty()) {
            checkPermission(user.getId(), userIdHeader, userRole);
        }

        return ResponseDataDTO.of(convertToDto(user));
    }

    /**
     * 모든 User 조회 (ADMIN만 가능)
     * GET /api/users
     * - Gateway가 보내준 X-User-Role 헤더로 권한 확인
     */
    @GetMapping
    public ResponseDataDTO<List<UserDto>> getAllUsers(
            @RequestHeader(value = "X-User-Role", required = false) String userRole) {
        log.info("Get all users, role: {}", userRole);

        // ADMIN 권한 체크
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
     * - 인증 없이 접근 가능 (Gateway에서 permitAll)
     */
    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public ResponseDataDTO<UserDto> createUser(@RequestBody UserCreateRequest request) {
        log.info("Create user: username={}, email={}", request.getUsername(), request.getEmail());
        User user = userService.registerUser(
                request.getUsername(),
                request.getPassword(),
                request.getEmail()
        );
        return ResponseDataDTO.of(convertToDto(user), "User created successfully");
    }

    /**
     * User 수정 (본인 또는 ADMIN만 가능)
     * PUT /api/users/{id}
     * - Gateway가 보내준 X-User-Id, X-User-Role 헤더로 권한 확인
     */
    @PutMapping("/{id}")
    public ResponseDataDTO<UserDto> updateUser(
            @PathVariable Long id,
            @RequestBody UserUpdateRequest request,
            @RequestHeader(value = "X-User-Id", required = false) String userIdHeader,
            @RequestHeader(value = "X-User-Role", required = false) String userRole) {
        log.info("Update user: id={}, requester={}", id, userIdHeader);

        // 권한 체크: 본인이거나 ADMIN이어야 함
        checkPermission(id, userIdHeader, userRole);

        User user = userService.findById(id);

        if (request.getEmail() != null) {
            user.setEmail(request.getEmail());
        }

        // Role 변경은 ADMIN만 가능
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
     * DELETE /api/users/{id}
     */
    @DeleteMapping("/{id}")
    public ResponseDataDTO<Void> deleteUser(
            @PathVariable Long id,
            @RequestHeader(value = "X-User-Id", required = false) String userIdHeader,
            @RequestHeader(value = "X-User-Role", required = false) String userRole) {
        log.info("Delete user: id={}, requester={}", id, userIdHeader);

        // 권한 체크: 본인이거나 ADMIN이어야 함
        checkPermission(id, userIdHeader, userRole);

        User user = userService.findById(id);
        userRepository.delete(user);

        return ResponseDataDTO.of(null, "User deleted successfully");
    }

    /**
     * User 존재 여부 확인
     * GET /api/users/{id}/exists
     */
    @GetMapping("/{id}/exists")
    public ResponseDataDTO<Boolean> existsById(@PathVariable Long id) {
        log.info("Check user existence: id={}", id);
        boolean exists = userRepository.existsById(id);
        return ResponseDataDTO.of(exists);
    }

    /**
     * User Entity -> UserDto 변환
     */
    private UserDto convertToDto(User user) {
        return UserDto.builder()
                .id(user.getId())
                .username(user.getUsername())
                .email(user.getEmail())
                .role(user.getRole())
                .createdAt(user.getCreatedAt())
                .updatedAt(user.getUpdatedAt())
                .build();
    }

    /**
     * 권한 체크: 본인 또는 ADMIN만 허용
     * - Gateway가 보내준 X-User-Id, X-User-Role 헤더 사용
     */
    private void checkPermission(Long targetUserId, String userIdHeader, String userRole) {
        // ADMIN이면 통과
        if (isAdmin(userRole)) {
            return;
        }

        // 본인 확인
        if (userIdHeader == null || userIdHeader.isEmpty()) {
            throw new AuthException("Authentication required");
        }

        try {
            Long requesterId = Long.parseLong(userIdHeader);
            if (!requesterId.equals(targetUserId)) {
                throw new AuthException("You can only modify your own information");
            }
        } catch (NumberFormatException e) {
            throw new AuthException("Invalid user ID");
        }
    }

    /**
     * 현재 사용자가 ADMIN인지 확인
     */
    private boolean isAdmin(String userRole) {
        return UserRole.isAdmin(userRole);
    }
}
