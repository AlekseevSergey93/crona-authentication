package com.cronagroup.authentication.config;

import com.cronagroup.authentication.common.web.RequestIdFilter;
import com.cronagroup.authentication.common.web.AccessLoggingFilter;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class WebConfiguration {

    @Bean
    public FilterRegistrationBean<RequestIdFilter> requestIdFilter() {
        FilterRegistrationBean<RequestIdFilter> registration = new FilterRegistrationBean<>();
        registration.setFilter(new RequestIdFilter());
        registration.addUrlPatterns("/*");
        registration.setOrder(-100);
        return registration;
    }

    @Bean
    public FilterRegistrationBean<AccessLoggingFilter> accessLoggingFilter() {
        FilterRegistrationBean<AccessLoggingFilter> registration = new FilterRegistrationBean<>();
        registration.setFilter(new AccessLoggingFilter());
        registration.addUrlPatterns("/*");
        registration.setOrder(-90);
        return registration;
    }
}
