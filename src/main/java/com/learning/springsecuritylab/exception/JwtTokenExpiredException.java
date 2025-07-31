package com.learning.springsecuritylab.exception;

public class JwtTokenExpiredException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    public JwtTokenExpiredException(String message) {
        super(message);
    }

    public JwtTokenExpiredException(String message, Throwable cause) {
        super(message, cause);
    }
}
