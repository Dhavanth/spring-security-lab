package com.learning.springsecuritylab.constants;

public interface Constants {
    // User Controller
    String USER_CONTROLLER = "/users";
    String SIGN_UP = "/signup";
    String CUSTOM_LOGIN = "/custom-login";
    String USER_TEST = "/user-test";
    String CHANGE_PASSWORD = "/change-password";
    String USER_PROFILE = "/user-profile";
    String FORGOT_PASSWORD = "/forgot-password";
    String RESET_PASSWORD = "/reset-password";

    // Authority
    String READ_AUTHORITY = "READ";
    String WRITE_AUTHORITY = "WRITE";

    // JWT
    String JWT_SECRET_KEY = "JWT_SECRET_KEY";
    String JWT_SECRET_VALUE_DEFAULT = "rcgEispYsrnIutgNwuvQxYbqZcXkJmFgkjgnkjvdkfvndvndkvnldkfvndflnvldfln";
    String JWT_HEADER = "Authorization";
}
