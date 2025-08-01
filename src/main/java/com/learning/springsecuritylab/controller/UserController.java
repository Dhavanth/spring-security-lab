package com.learning.springsecuritylab.controller;

import com.learning.springsecuritylab.constants.Constants;
import com.learning.springsecuritylab.dto.*;
import com.learning.springsecuritylab.entity.UserEntity;
import com.learning.springsecuritylab.repository.UserRepository;
import com.learning.springsecuritylab.service.PasswordResetTokenService;
import com.learning.springsecuritylab.service.RefreshTokenService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import java.util.Optional;

@RestController
@RequiredArgsConstructor
@RequestMapping(value = Constants.USER_CONTROLLER)
public class UserController {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final PasswordResetTokenService passwordResetTokenService;
    private final RefreshTokenService refreshTokenService;

    @PostMapping(value = Constants.SIGN_UP)
    public String signUp(@RequestBody  SignUpRequestDto signUpRequestDto) {
        String userName = signUpRequestDto.getUserName();
        String emailId = signUpRequestDto.getEmailId();
        String password = signUpRequestDto.getPassword();
        String role = signUpRequestDto.getRole();
        Optional<UserEntity> optionalUserEntity = userRepository.findByUserName(userName);
        if (optionalUserEntity.isPresent()) {
            return "User already exists with username: " + userName;
        }
        UserEntity newUserEntity = new UserEntity();
        newUserEntity.setUserName(userName);
        newUserEntity.setEmailId(emailId);
        newUserEntity.setPassword(passwordEncoder.encode(password));
        newUserEntity.setRole(role);
        UserEntity savedUser = userRepository.save(newUserEntity);

        return "User registered successfully with ID: " + savedUser.getId();
    }

    @GetMapping(value = Constants.CUSTOM_LOGIN)
    public String login(Authentication authentication) {
        Optional<UserEntity> optionalUserEntity = userRepository.findByUserName(authentication.getName());
        if (optionalUserEntity.isEmpty()) {
            return "User not found with username: " + authentication.getName();
        }
        SecurityContextHolder.getContext().setAuthentication(authentication);
        return "User logged in successfully with username: " + optionalUserEntity.get().getUserName();
    }

    @PostMapping(value = Constants.CHANGE_PASSWORD)
    public String changePassword(@RequestBody ChangePasswordDto changePasswordDto) {
        //String userName = changePasswordDto.getUserName();
        String userName = SecurityContextHolder.getContext().getAuthentication().getName();
        String newPassword = changePasswordDto.getPassword();
        Optional<UserEntity> optionalUserEntity = userRepository.findByUserName(userName);
        if (optionalUserEntity.isEmpty()) {
            return "User not found with username: " + userName;
        }
        UserEntity userEntity = optionalUserEntity.get();
        userEntity.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(userEntity);
        return "Password changed successfully for user: " + userName;
    }

    @GetMapping(value = Constants.USER_TEST)
    public String userTest() {
        return "User Test Page for Login Test using Basic Authentication";
    }

    @PostMapping(value = Constants.FORGOT_PASSWORD)
    public String forgotPassword(@RequestParam String userName) {
        return passwordResetTokenService.createPasswordResetToken(userName);
    }

    @PostMapping(value = Constants.RESET_PASSWORD)
    public String resetPassword(@RequestParam String token, @RequestBody ResetPasswordDto resetPasswordDto) {
        return passwordResetTokenService.resetPasswordUsingToken(token, resetPasswordDto.getNewPassword());
    }

    @GetMapping(value = Constants.USER_PROFILE)
    public String userProfile() {
        SecurityContext securityContext = SecurityContextHolder.getContext();
        String userName = securityContext.getAuthentication().getName();
        String role = securityContext.getAuthentication().getAuthorities().toString();
        String emailId = userRepository.findByUserName(userName).get().getEmailId();
        return "User Profile: \n" +
                "==========================================\n" +
                "Username: " + userName + "\n" +
                "Role: " + role + "\n" +
                "Email ID: " + emailId;
    }

    @PostMapping(value = Constants.REFRESH_TOKEN)
    public ResponseEntity<?> generateNewRefreshTokenAndAccessToken
            (HttpServletRequest request, HttpServletResponse response) {
        RefreshTokenResponseDto refreshTokenResponseDto =
                refreshTokenService.generateNewRefreshTokenAndAccessToken(request, response);

        if (refreshTokenResponseDto.isRefreshTokenNull()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Refresh token is null. Please login again.");
        }

        if (refreshTokenResponseDto.isRefreshTokenExpired()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Refresh token is expired. Please login again.");
        }

        return ResponseEntity.ok(refreshTokenResponseDto);
    }
}

