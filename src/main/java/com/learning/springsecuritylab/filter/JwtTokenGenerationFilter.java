package com.learning.springsecuritylab.filter;

import com.learning.springsecuritylab.constants.Constants;
import com.learning.springsecuritylab.service.RefreshTokenService;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.springframework.core.env.Environment;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Date;
import java.util.stream.Collectors;

@Component
@AllArgsConstructor
@NoArgsConstructor
public class JwtTokenGenerationFilter extends OncePerRequestFilter {
    private String customLoginRequest = Constants.USER_CONTROLLER + Constants.CUSTOM_LOGIN;
    private String userProfileRequest = Constants.USER_CONTROLLER + Constants.USER_PROFILE;
    private RefreshTokenService refreshTokenService;

    public JwtTokenGenerationFilter(RefreshTokenService refreshTokenService) {
        this.refreshTokenService = refreshTokenService;
    }

    /**
     * @param request
     * @param response
     * @param filterChain
     * @throws ServletException
     * @throws IOException
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (null != authentication) {
            Environment environment = getEnvironment();
            if (null != environment) {
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
                        .claim("username", authentication.getName())
                        .claim("authorities", authentication.getAuthorities()
                                .stream()
                                .map(GrantedAuthority::getAuthority)
                                .collect(Collectors.joining(",")))
                        .claim("issuedAt", issuedAt)
                        .claim("expiresAt", expiresAt)
                        .signWith(secretKey)
                        .compact();
                response.setHeader(Constants.JWT_HEADER, jwtToken);

                String refreshToken = refreshTokenService.createRefreshToken(authentication.getName());
                // Send refresh token to client as HttpOnly cookie
                Cookie refreshTokenCookie = new Cookie(Constants.REFRESH_TOKEN_COOKIE_NAME, refreshToken);
                refreshTokenCookie.setHttpOnly(true); // Prevents JavaScript access
                refreshTokenCookie.setPath("/"); // Make it available to all paths
                refreshTokenCookie.setMaxAge(30 * 24 * 60 * 60); // 30 days expiration
                response.addCookie(refreshTokenCookie);
            }
        }
        // Continue with the filter chain
        filterChain.doFilter(request, response);
    }


    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        // Filter should be applied only to log in request
        return !request.getServletPath().equals(customLoginRequest);
    }
}
