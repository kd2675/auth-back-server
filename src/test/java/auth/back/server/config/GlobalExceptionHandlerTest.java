package auth.back.server.config;

import auth.back.server.service.UserAlreadyExistsException;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import web.common.core.response.base.dto.ResponseErrorDTO;

import static org.assertj.core.api.Assertions.assertThat;

class GlobalExceptionHandlerTest {

    private final GlobalExceptionHandler exceptionHandler = new GlobalExceptionHandler();

    @Test
    void handleUserAlreadyExists_duplicateSignup_returnsConflict() {
        ResponseEntity<ResponseErrorDTO> response = exceptionHandler.handleUserAlreadyExists(
                new UserAlreadyExistsException("Username already exists")
        );

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
    }
}
