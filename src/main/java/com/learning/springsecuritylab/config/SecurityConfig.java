package com.learning.springsecuritylab.config;

import com.learning.springsecuritylab.constants.Constants;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.password.CompromisedPasswordChecker;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.password.HaveIBeenPwnedRestApiPasswordChecker;

import javax.sql.DataSource;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    private String signUpRequest = Constants.USER_CONTROLLER + Constants.SIGN_UP;
    private String customLoginRequest = Constants.USER_CONTROLLER + Constants.CUSTOM_LOGIN;
    private String forgotPasswordRequest = Constants.USER_CONTROLLER + Constants.FORGOT_PASSWORD;
    private String resetPasswordRequest = Constants.USER_CONTROLLER + Constants.RESET_PASSWORD;

    @Bean
    public AuthenticationManager authenticationManager(HttpSecurity http,
                                                       CustomAuthenticationProviderImpl customAuthenticationProviderImpl)
            throws Exception {
        return http.getSharedObject(AuthenticationManagerBuilder.class)
                .authenticationProvider(customAuthenticationProviderImpl)
                .build();
    }
    @Bean
    public SecurityFilterChain customSecurityFilterChain(HttpSecurity http)
            throws Exception {
        http.csrf(csrfConfig -> csrfConfig.disable());
        http.authorizeHttpRequests(
                requests -> requests
                        .requestMatchers(signUpRequest, customLoginRequest, forgotPasswordRequest, resetPasswordRequest).permitAll()
                        .anyRequest().authenticated());
        http.formLogin(withDefaults());
        http.httpBasic(withDefaults()); // Pending: custom auth entry point
        //http.authenticationProvider(customAuthenticationProviderImpl);
        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        // Returns BcryptPasswordEncoder by default
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    public CompromisedPasswordChecker compromisedPasswordChecker() {
        // Checks passwords against Have I Been Pwned API
        return new HaveIBeenPwnedRestApiPasswordChecker();
    }

    @Bean
    public UserDetailsService userDetailsService(DataSource dataSource) {
        return new JdbcUserDetailsManager(dataSource);
    }

    @Bean
    public InitializingBean setSecurityContextHolder() {
        return () -> SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_THREADLOCAL);
    }
}
