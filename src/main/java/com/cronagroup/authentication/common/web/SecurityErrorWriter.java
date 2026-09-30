package com.cronagroup.authentication.common.web;

import com.cronagroup.authentication.common.error.ErrorResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.time.Instant;

@Component
public class SecurityErrorWriter {

    private final ObjectMapper objectMapper;

    public SecurityErrorWriter(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public void write(
            HttpServletResponse response,
            HttpServletRequest request,
            HttpStatus status,
            String code,
            String message
    ) throws IOException {
        Object requestId = request.getAttribute(RequestIdFilter.REQUEST_ATTRIBUTE);
        String requestIdValue = requestId instanceof String value
                ? value
                : request.getHeader(RequestIdFilter.HEADER_NAME);
        ErrorResponse error = new ErrorResponse(
                Instant.now(),
                status.value(),
                code,
                message,
                requestIdValue
        );
        response.setStatus(status.value());
        response.setContentType("application/json");
        response.getWriter().write(objectMapper.writeValueAsString(error));
    }
}
