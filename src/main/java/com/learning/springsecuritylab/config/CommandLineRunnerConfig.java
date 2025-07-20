package com.learning.springsecuritylab.config;

import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class CommandLineRunnerConfig {

    @Bean
    public CommandLineRunner printSecurityFilters(FilterChainProxy filterChainProxy) {
        return args -> {
            System.out.println("=== Spring Security Filter Chains ===");
            for (SecurityFilterChain chain : filterChainProxy.getFilterChains()) {
                System.out.println("Filter chain:");
                chain.getFilters().forEach(filter ->
                        System.out.println(" - " + filter.getClass().getName())
                );
            }
            System.out.println("=== End ===");
        };
    }
}
