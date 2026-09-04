package auth.back.server.service;

import auth.common.core.exception.AuthException;

/** 회원가입 아이디 또는 이메일이 이미 사용 중일 때 발생하는 충돌 예외다. */
public class UserAlreadyExistsException extends AuthException {
    public UserAlreadyExistsException(String message) {
        super(message);
    }
}
