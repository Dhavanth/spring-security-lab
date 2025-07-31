package com.learning.springsecuritylab.filter;

import com.learning.springsecuritylab.constants.Constants;
import com.learning.springsecuritylab.exception.JwtTokenExpiredException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Date;

public class JwtTokenValidationFilter extends OncePerRequestFilter {
    private String customLoginRequest = Constants.USER_CONTROLLER + Constants.CUSTOM_LOGIN;
    private String userProfileRequest = Constants.USER_CONTROLLER + Constants.USER_PROFILE;

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
        String jwtToken = request.getHeader(Constants.JWT_HEADER);
        if (null != jwtToken) {
            try {
                Environment environment = getEnvironment();
                if (null != environment) {
                    String secret = environment.getProperty(Constants.JWT_SECRET_KEY,
                            Constants.JWT_SECRET_VALUE_DEFAULT);
                    SecretKey secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
                    if (null != secretKey) {
                        // Parse the JWT token and validate the signature using the secret key
                        Claims claims = Jwts.parser()
                                .verifyWith(secretKey)
                                .build()
                                .parseSignedClaims(jwtToken).getPayload();
                        // Check if the token is expired
                        String expiredAtString = String.valueOf(claims.get("expiresAt"));
                        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
                        LocalDateTime expDateTime = LocalDateTime.parse(expiredAtString, formatter);
                        if (expDateTime != null && expDateTime.isBefore(LocalDateTime.now())) {
                            throw new JwtTokenExpiredException("JWT Token is expired at" + expDateTime +
                                    "Please login again to fetch latest JWT Token.");
                        }
                        String username = String.valueOf(claims.get("username"));
                        String authorities = String.valueOf(claims.get("authorities"));
                        // Create an authentication object with the username and authorities where authenticated is set to true
                        Authentication authentication =
                                new UsernamePasswordAuthenticationToken(username, null,
                                        AuthorityUtils.commaSeparatedStringToAuthorityList(authorities));
                        // Set the authentication object in the security context
                        SecurityContextHolder.getContext().setAuthentication(authentication);
                    }
                }
            } catch (Exception e) {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.setContentType("application/json");
                response.getWriter().write("{\"error\": \"" + "Invalid JWT Token: " + e.getMessage() + "\"}");
                //throw new BadCredentialsException("Invalid JWT Token: " + e.getMessage());
                return;
            }
        }
        filterChain.doFilter(request, response);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        // Filter should be applied only to requests other than log in request
        return request.getServletPath().equals(customLoginRequest);
    }
}
