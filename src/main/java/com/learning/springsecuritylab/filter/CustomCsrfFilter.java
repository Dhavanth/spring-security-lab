package com.learning.springsecuritylab.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class CustomCsrfFilter extends OncePerRequestFilter {

    /**
     * @param request
     * @param response
     * @param filterChain
     * @throws ServletException
     * @throws IOException
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        CsrfToken csrfTokenFetchedManually = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
        // How does the request is setting the CSRF token attribute?
        // It is set by the CsrfFilter which is part of the Spring Security filter chain.
        csrfTokenFetchedManually.getToken();
        filterChain.doFilter(request, response);
    }
}
