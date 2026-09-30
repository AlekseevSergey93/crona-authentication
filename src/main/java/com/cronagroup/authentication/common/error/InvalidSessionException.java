package com.cronagroup.authentication.common.error;

import org.springframework.http.HttpStatus;

public class InvalidSessionException extends ApiException {

    public InvalidSessionException() {
        super(HttpStatus.UNAUTHORIZED, "INVALID_SESSION", "Session is invalid");
    }
}
