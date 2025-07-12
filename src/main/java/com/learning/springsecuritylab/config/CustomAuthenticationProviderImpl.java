package com.learning.springsecuritylab.config;

import com.learning.springsecuritylab.entity.UserEntity;
import com.learning.springsecuritylab.service.CustomUserDetailsServiceImpl;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class CustomAuthenticationProviderImpl implements AuthenticationProvider {
    private final CustomUserDetailsServiceImpl customUserDetailsServiceImpl;
    private final PasswordEncoder passwordEncoder;
    /**
     * @param authentication the authentication request object.
     * @return
     * @throws AuthenticationException
     */
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String userNameInAuthObj = authentication.getName();
        String passwordInAuthObj = authentication.getCredentials().toString();
        UserDetails userDetails = customUserDetailsServiceImpl.loadUserByUsername(userNameInAuthObj);
        String passwordInDb = userDetails.getPassword();
        if (!passwordEncoder.matches(passwordInAuthObj, passwordInDb)) {
            throw new BadCredentialsException("Bad credentials");
        }
        return new UsernamePasswordAuthenticationToken(userDetails, passwordInDb, userDetails.getAuthorities());
    }

    /**
     * @param authentication
     * @return
     */
    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
