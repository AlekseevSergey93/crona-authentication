package com.cronagroup.authentication.common.error;

import org.springframework.http.HttpStatus;

public class DuplicateUserException extends ApiException {

    public DuplicateUserException() {
        super(HttpStatus.CONFLICT, "USER_ALREADY_EXISTS", "A user with this email already exists");
    }
}
