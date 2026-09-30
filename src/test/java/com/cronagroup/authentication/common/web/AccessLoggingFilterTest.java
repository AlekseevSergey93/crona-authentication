package com.cronagroup.authentication.common.web;

import com.cronagroup.authentication.common.security.BearerAuthenticationFilter;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class AccessLoggingFilterTest {

    @Test
    void logsSafeIdentifiersWithoutCredentialsOrAuthorizationHeader() throws Exception {
        Logger logger = (Logger) LoggerFactory.getLogger(AccessLoggingFilter.class);
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);

        try {
            MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/me");
            request.addHeader("Authorization", "Bearer secret-jwt");
            request.setAttribute(RequestIdFilter.REQUEST_ATTRIBUTE, "request-123");
            request.setAttribute(BearerAuthenticationFilter.USER_ID_ATTRIBUTE, "user-123");
            request.setAttribute(BearerAuthenticationFilter.SESSION_ID_ATTRIBUTE, "session-123");
            MockHttpServletResponse response = new MockHttpServletResponse();
            FilterChain chain = mock(FilterChain.class);

            new AccessLoggingFilter().doFilter(request, response, chain);

            String message = appender.list.get(0).getFormattedMessage();
            assertThat(message).contains("request-123", "user-123", "session-123");
            assertThat(message).doesNotContain("secret-jwt", "Authorization", "Bearer");
        } finally {
            logger.detachAppender(appender);
        }
    }
}
