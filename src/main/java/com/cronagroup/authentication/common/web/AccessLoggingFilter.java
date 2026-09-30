package com.cronagroup.authentication.common.web;

import com.cronagroup.authentication.common.security.BearerAuthenticationFilter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Optional;

public class AccessLoggingFilter extends OncePerRequestFilter {

    private static final Logger LOGGER = LoggerFactory.getLogger(AccessLoggingFilter.class);

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {
        long startedAt = System.nanoTime();
        try {
            filterChain.doFilter(request, response);
        } finally {
            String outcome = response.getStatus() >= 500
                    ? "error"
                    : response.getStatus() >= 400 ? "rejected" : "success";
            LOGGER.info(
                    "http_request operation={} method={} path={} requestId={} status={} outcome={} durationMs={} userId={} sessionId={}",
                    request.getRequestURI(),
                    request.getMethod(),
                    request.getRequestURI(),
                    request.getAttribute(RequestIdFilter.REQUEST_ATTRIBUTE),
                    response.getStatus(),
                    outcome,
                    (System.nanoTime() - startedAt) / 1_000_000,
                    safeAttribute(request, BearerAuthenticationFilter.USER_ID_ATTRIBUTE),
                    safeAttribute(request, BearerAuthenticationFilter.SESSION_ID_ATTRIBUTE)
            );
        }
    }

    private static String safeAttribute(HttpServletRequest request, String name) {
        return Optional.ofNullable(request.getAttribute(name))
                .map(Object::toString)
                .orElse("-");
    }
}
