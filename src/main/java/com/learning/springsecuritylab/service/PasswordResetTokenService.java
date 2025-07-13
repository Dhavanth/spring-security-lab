package com.learning.springsecuritylab.service;

import com.learning.springsecuritylab.entity.PasswordResetToken;
import com.learning.springsecuritylab.entity.UserEntity;
import com.learning.springsecuritylab.repository.PasswordResetTokenRepository;
import com.learning.springsecuritylab.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class PasswordResetTokenService {

    private final PasswordResetTokenRepository tokenRepository;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public String createPasswordResetToken(String userName) {
        Optional<UserEntity> optionalUser = userRepository.findByUserName(userName);
        if (optionalUser.isEmpty()) {
            throw new UsernameNotFoundException("User not found with username: " + userName);
        }
        UserEntity user = optionalUser.get();
        String token = UUID.randomUUID().toString();
        PasswordResetToken passwordResetToken = new PasswordResetToken();
        passwordResetToken.setToken(token);
        passwordResetToken.setUserId(user.getId());
        passwordResetToken.setExpiryDate(LocalDateTime.now().plusMinutes(10)); // Token valid for 10 minutes
        passwordResetToken.setIsDeleted(false);

        tokenRepository.save(passwordResetToken);
        System.out.println("Password reset token created for user: " + userName + ", Token: " + token);

        return "Reset password link: " +
                "http://localhost:8080/users/reset-password?token=" + token + "\n" +
                "Please use this link to reset your password. The token is valid for 10 minutes.";
    }

    public String resetPasswordUsingToken(String token, String newPassword) {
        PasswordResetToken passwordResetToken = tokenRepository.findByToken(token)
                .orElseThrow(() -> new IllegalArgumentException("Invalid password reset token"));

        if (passwordResetToken.getIsDeleted() ||
                passwordResetToken.getExpiryDate().isBefore(LocalDateTime.now())) {
            throw new IllegalArgumentException("Password reset token has expired");
        }

        UserEntity user = userRepository.findById(passwordResetToken.getUserId()).get();
        String encodedPassword = passwordEncoder.encode(newPassword);
        System.out.println(encodedPassword);
        user.setPassword(encodedPassword);
        UserEntity savedUser = userRepository.save(user);
        System.out.println(savedUser);

        // Soft delete the token with a flag
        passwordResetToken.setIsDeleted(true);
        tokenRepository.save(passwordResetToken);

        return "Password reset successfully for user: " + savedUser.getUserName() + ", userId: " + savedUser.getId();
    }
}
