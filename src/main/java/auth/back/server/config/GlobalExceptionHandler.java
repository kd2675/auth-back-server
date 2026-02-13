package auth.back.server.config;

import auth.common.core.exception.AuthException;
import auth.common.core.exception.InvalidTokenException;
import auth.common.core.exception.TokenExpiredException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import web.common.core.response.base.dto.ResponseErrorDTO;
import web.common.core.response.base.vo.Code;

/**
 * 전역 예외 처리기
 * - 모든 예외를 web-common-core의 ResponseErrorDTO로 통일
 */
@RestControllerAdvice
@Slf4j
public class GlobalExceptionHandler {

    /**
     * 인증 실패 (로그인 실패)
     */
    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<ResponseErrorDTO> handleBadCredentials(BadCredentialsException e) {
        log.warn("Bad credentials: {}", e.getMessage());
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(ResponseErrorDTO.of(Code.NOT_MATCH_PASSWORD, "Invalid username or password"));
    }

    /**
     * 사용자를 찾을 수 없음
     */
    @ExceptionHandler(UsernameNotFoundException.class)
    public ResponseEntity<ResponseErrorDTO> handleUsernameNotFound(UsernameNotFoundException e) {
        log.warn("User not found: {}", e.getMessage());
        return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(ResponseErrorDTO.of(Code.NO_SEARCH_USER, e.getMessage()));
    }

    /**
     * 토큰 만료
     */
    @ExceptionHandler(TokenExpiredException.class)
    public ResponseEntity<ResponseErrorDTO> handleTokenExpired(TokenExpiredException e) {
        log.warn("Token expired: {}", e.getMessage());
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(ResponseErrorDTO.of(Code.TOKEN_EXPIRED, e.getMessage()));
    }

    /**
     * 유효하지 않은 토큰
     */
    @ExceptionHandler(InvalidTokenException.class)
    public ResponseEntity<ResponseErrorDTO> handleInvalidToken(InvalidTokenException e) {
        log.warn("Invalid token: {}", e.getMessage());
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(ResponseErrorDTO.of(Code.TOKEN_MALFORMED, e.getMessage()));
    }

    /**
     * 인증 예외 (일반)
     */
    @ExceptionHandler(AuthException.class)
    public ResponseEntity<ResponseErrorDTO> handleAuthException(AuthException e) {
        log.warn("Auth exception: {}", e.getMessage());
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(ResponseErrorDTO.of(Code.UNAUTHORIZED, e.getMessage()));
    }


    /**
     * 일반 예외
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ResponseErrorDTO> handleGeneral(Exception e) {
        log.error("Unexpected error: ", e);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(ResponseErrorDTO.of(Code.INTERNAL_SERVER_ERROR, e.getMessage()));
    }
}
