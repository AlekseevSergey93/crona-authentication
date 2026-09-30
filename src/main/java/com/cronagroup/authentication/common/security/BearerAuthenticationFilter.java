package com.cronagroup.authentication.common.security;

import com.cronagroup.authentication.common.web.SecurityErrorWriter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.dao.DataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Optional;

@Component
public class BearerAuthenticationFilter extends OncePerRequestFilter {

    public static final String USER_ID_ATTRIBUTE = BearerAuthenticationFilter.class.getName() + ".userId";
    public static final String SESSION_ID_ATTRIBUTE = BearerAuthenticationFilter.class.getName() + ".sessionId";

    private final JwtTokenService jwtTokenService;
    private final ObjectProvider<RedisSessionRepository> sessionRepositoryProvider;
    private final SecurityErrorWriter errorWriter;

    public BearerAuthenticationFilter(
            JwtTokenService jwtTokenService,
            ObjectProvider<RedisSessionRepository> sessionRepositoryProvider,
            SecurityErrorWriter errorWriter
    ) {
        this.jwtTokenService = jwtTokenService;
        this.sessionRepositoryProvider = sessionRepositoryProvider;
        this.errorWriter = errorWriter;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        return "/api/auth/register".equals(path)
                || "/api/auth/login".equals(path)
                || "/api/auth/refresh".equals(path)
                || "/api/auth/logout".equals(path);
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {
        String authorization = request.getHeader("Authorization");
        if (authorization == null) {
            filterChain.doFilter(request, response);
            return;
        }

        String token = bearerToken(authorization);
        if (token == null) {
            errorWriter.write(response, request, HttpStatus.UNAUTHORIZED, "UNAUTHORIZED", "Authentication is required");
            return;
        }

        try {
            JwtTokenService.AccessTokenClaims claims = jwtTokenService.validate(token);
            RedisSessionRepository sessionRepository = sessionRepositoryProvider.getIfAvailable();
            if (sessionRepository == null) {
                errorWriter.write(
                        response,
                        request,
                        HttpStatus.SERVICE_UNAVAILABLE,
                        "DEPENDENCY_UNAVAILABLE",
                        "Session persistence is unavailable"
                );
                return;
            }

            Optional<RedisSessionRepository.SessionRecord> session =
                    sessionRepository.find(claims.sessionId());
            if (session.isEmpty() || !claims.userId().equals(session.get().userId())) {
                errorWriter.write(response, request, HttpStatus.UNAUTHORIZED, "UNAUTHORIZED", "Authentication is required");
                return;
            }

            AuthenticatedUser authenticatedUser = new AuthenticatedUser(claims.userId(), claims.sessionId());
            request.setAttribute(USER_ID_ATTRIBUTE, claims.userId().toString());
            request.setAttribute(SESSION_ID_ATTRIBUTE, claims.sessionId().toString());
            SecurityContextHolder.getContext().setAuthentication(
                    new UsernamePasswordAuthenticationToken(
                            authenticatedUser,
                            null,
                            AuthorityUtils.NO_AUTHORITIES
                    )
            );
            filterChain.doFilter(request, response);
        } catch (IllegalArgumentException exception) {
            errorWriter.write(response, request, HttpStatus.UNAUTHORIZED, "UNAUTHORIZED", "Authentication is required");
        } catch (DataAccessException exception) {
            errorWriter.write(
                    response,
                    request,
                    HttpStatus.SERVICE_UNAVAILABLE,
                    "DEPENDENCY_UNAVAILABLE",
                    "Session persistence is unavailable"
            );
        } finally {
            SecurityContextHolder.clearContext();
        }
    }

    private static String bearerToken(String authorization) {
        int separator = authorization.indexOf(' ');
        if (separator < 0 || !"Bearer".equalsIgnoreCase(authorization.substring(0, separator))) {
            return null;
        }
        String token = authorization.substring(separator + 1).trim();
        return token.isEmpty() ? null : token;
    }
}
