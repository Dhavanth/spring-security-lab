package com.learning.springsecuritylab.service;

import com.learning.springsecuritylab.constants.Constants;
import com.learning.springsecuritylab.dto.RefreshTokenResponseDto;
import com.learning.springsecuritylab.entity.RefreshToken;
import com.learning.springsecuritylab.entity.UserEntity;
import com.learning.springsecuritylab.exception.RefreshTokenNotFoundException;
import com.learning.springsecuritylab.repository.RefreshTokenRepository;
import com.learning.springsecuritylab.repository.UserRepository;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.core.env.Environment;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;
    private final CustomUserDetailsServiceImpl customUserDetailsService;
    private final Environment environment;

    public String createRefreshToken(String userName) {
        Optional<UserEntity> optionalUser = userRepository.findByUserName(userName);
        if (optionalUser.isEmpty()) {
            throw new UsernameNotFoundException("User not found with username: " + userName);
        }
        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setRefreshToken(UUID.randomUUID().toString());
        refreshToken.setUserId(optionalUser.get().getId());
        refreshToken.setExpiryDate(LocalDateTime.now().plusDays(30)); // Token valid for 30 days
        RefreshToken savedRefreshToken = refreshTokenRepository.save(refreshToken);

        return savedRefreshToken.getRefreshToken();
    }

    public RefreshToken getRefreshToken(String token) {
        Optional<RefreshToken> optionalRefreshToken = refreshTokenRepository.findByRefreshToken(token);
        if (optionalRefreshToken.isEmpty()) {
            throw new RefreshTokenNotFoundException("Refresh token not found: " + token);
        }
        return optionalRefreshToken.get();
    }

    public boolean isRefreshTokenValid(String token) {
        RefreshToken refreshToken = getRefreshToken(token);
        return refreshToken.getExpiryDate().isAfter(LocalDateTime.now());
    }


    // Token deletion occur when user logs out or change-password or password-reset scenarios
    public void deleteRefreshTokenById(Long refreshTokenId) {
        refreshTokenRepository.deleteRefreshTokenById(refreshTokenId);
    }

    // Token deletion occur when user logs out or change-password or password-reset scenarios
    public void deleteByUserId(Long userId) {
        refreshTokenRepository.deleteByUserId(userId);
    }

    @Transactional (rollbackFor = Exception.class, propagation = Propagation.REQUIRED)
    public RefreshTokenResponseDto generateNewRefreshTokenAndAccessToken
            (HttpServletRequest request, HttpServletResponse response) {
        RefreshTokenResponseDto refreshTokenResponseDto = new RefreshTokenResponseDto();
        // Extract the current refresh token from the request cookies
        String currentRefreshToken = Arrays.stream(request.getCookies())
                .filter(cookie -> Constants.REFRESH_TOKEN_COOKIE_NAME.equals(cookie.getName()))
                .findFirst()
                .map(Cookie::getValue)
                .orElse(null);

        if (currentRefreshToken == null) {
            refreshTokenResponseDto.setRefreshTokenNull(true);
            return refreshTokenResponseDto;
        }

        // Fetch the refresh token from the database using the current refresh token
        RefreshToken refreshToken = getRefreshToken(currentRefreshToken);

        // Validate the current refresh token
        if (!isRefreshTokenValid(refreshToken.getRefreshToken())) {
            refreshTokenResponseDto.setRefreshTokenExpired(true);
            // Delete the expired refresh token from the database
            deleteRefreshTokenById(refreshToken.getId());
            return refreshTokenResponseDto;
        }

        // Fetch the user associated with the current refresh token
        Optional<UserEntity> optionalUser = userRepository.findById(refreshToken.getUserId());
        if (optionalUser.isEmpty()) {
            throw new UsernameNotFoundException("User not found with ID: " + refreshToken.getUserId());
        }

        // Generate a new access token (JWT)
        String userName = optionalUser.get().getUserName();
        UserDetails userDetails = customUserDetailsService.loadUserByUsername(userName);

        String jwtSecretValue = environment.getProperty(Constants.JWT_SECRET_KEY, Constants.JWT_SECRET_VALUE_DEFAULT);
        // Secret key to sign the JWT token
        SecretKey secretKey = Keys.hmacShaKeyFor(jwtSecretValue.getBytes(StandardCharsets.UTF_8));
        // Generate JWT token
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
        String issuedAt = LocalDateTime.now().format(formatter);
        String expiresAt = LocalDateTime.now().plusMinutes(5).format(formatter);

        String jwtToken = Jwts.builder()
                .issuer("SpringSecurityLab")
                .subject("JWT Token")
                .claim("username", userDetails.getUsername())
                .claim("authorities", userDetails.getAuthorities()
                        .stream()
                        .map(GrantedAuthority::getAuthority)
                        .collect(Collectors.joining(",")))
                .claim("issuedAt", issuedAt)
                .claim("expiresAt", expiresAt)
                .signWith(secretKey)
                .compact();
        response.setHeader(Constants.JWT_HEADER, jwtToken);
        refreshTokenResponseDto.setAccessToken(jwtToken);

        // Delete the current refresh token & Generate a new refresh token
        deleteRefreshTokenById(refreshToken.getId());
        String newRefreshToken = createRefreshToken(userName);

        // Update the response with the new refresh token as an HttpOnly cookie
        Cookie refreshTokenCookie = new Cookie(Constants.REFRESH_TOKEN_COOKIE_NAME, newRefreshToken);
        refreshTokenCookie.setHttpOnly(true); // Prevents JavaScript access
        refreshTokenCookie.setPath("/"); // Make it available to all paths
        refreshTokenCookie.setMaxAge(30 * 24 * 60 * 60);
        response.addCookie(refreshTokenCookie);

        refreshTokenResponseDto.setRefreshToken(newRefreshToken);

        return refreshTokenResponseDto;
    }

}
