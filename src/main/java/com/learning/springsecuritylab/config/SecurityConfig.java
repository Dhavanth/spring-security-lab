package com.learning.springsecuritylab.config;

import com.learning.springsecuritylab.constants.Constants;
import com.learning.springsecuritylab.filter.CustomCsrfFilter;
import com.learning.springsecuritylab.filter.JwtTokenGenerationFilter;
import com.learning.springsecuritylab.filter.JwtTokenValidationFilter;
import com.learning.springsecuritylab.service.RefreshTokenService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.password.CompromisedPasswordChecker;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.password.HaveIBeenPwnedRestApiPasswordChecker;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import javax.sql.DataSource;

import java.util.Arrays;
import java.util.Collections;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    private String signUpRequest = Constants.USER_CONTROLLER + Constants.SIGN_UP;
    private String customLoginRequest = Constants.USER_CONTROLLER + Constants.CUSTOM_LOGIN;
    private String forgotPasswordRequest = Constants.USER_CONTROLLER + Constants.FORGOT_PASSWORD;
    private String resetPasswordRequest = Constants.USER_CONTROLLER + Constants.RESET_PASSWORD;
    private String changePasswordRequest = Constants.USER_CONTROLLER + Constants.CHANGE_PASSWORD;
    private String userProfileRequest = Constants.USER_CONTROLLER + Constants.USER_PROFILE;
    private String refreshTokenRequest = Constants.USER_CONTROLLER + Constants.REFRESH_TOKEN;

    @Bean
    public JwtTokenGenerationFilter jwtTokenGenerationFilter(RefreshTokenService refreshTokenService) {
        return new JwtTokenGenerationFilter(refreshTokenService);
    }


    @Bean
    public AuthenticationManager authenticationManager(HttpSecurity http,
                                                       CustomAuthenticationProviderImpl customAuthenticationProviderImpl)
            throws Exception {
        return http.getSharedObject(AuthenticationManagerBuilder.class)
                .authenticationProvider(customAuthenticationProviderImpl)
                .build();
    }
    @Bean
    public SecurityFilterChain customSecurityFilterChain(HttpSecurity http, JwtTokenGenerationFilter jwtTokenGenerationFilter)
            throws Exception {
        // CORS Configuration
        http.cors(corsCustomizer -> corsCustomizer.configurationSource(new CorsConfigurationSource() {
            @Override
            public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
                CorsConfiguration corsConfiguration = new CorsConfiguration();
                corsConfiguration.setAllowedOrigins(Collections.singletonList("*")); // Allow all origins
                corsConfiguration.setAllowedMethods(Collections.singletonList("*"));
                corsConfiguration.setAllowCredentials(true);
                corsConfiguration.setAllowedHeaders(Collections.singletonList("*"));
                corsConfiguration.setMaxAge(3600L);
                corsConfiguration.setExposedHeaders(Arrays.asList(Constants.JWT_HEADER));

                return corsConfiguration;
            }
        }));

        // CSRF Configuration
        CsrfTokenRequestAttributeHandler csrfTokenRequestAttributeHandler = new CsrfTokenRequestAttributeHandler();
        http.sessionManagement(
                sessionConfig -> sessionConfig.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        http.csrf(csrfConfig -> csrfConfig.csrfTokenRequestHandler(csrfTokenRequestAttributeHandler)
                        .ignoringRequestMatchers(signUpRequest, customLoginRequest, refreshTokenRequest)
                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()))
                .addFilterAfter(new CustomCsrfFilter(), BasicAuthenticationFilter.class);
        http.authorizeHttpRequests(
                requests -> requests
                        .requestMatchers(signUpRequest, customLoginRequest, forgotPasswordRequest, resetPasswordRequest, refreshTokenRequest).permitAll()
                        .requestMatchers(changePasswordRequest).hasAnyAuthority(Constants.WRITE_AUTHORITY, Constants.READ_AUTHORITY)
                        .requestMatchers(userProfileRequest).hasAnyAuthority(Constants.WRITE_AUTHORITY, Constants.READ_AUTHORITY)
                        .anyRequest().authenticated());
        http.addFilterAfter(jwtTokenGenerationFilter, BasicAuthenticationFilter.class);
        http.addFilterBefore(new JwtTokenValidationFilter(), BasicAuthenticationFilter.class);
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
