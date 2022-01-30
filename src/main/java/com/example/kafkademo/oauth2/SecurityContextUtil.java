package com.example.kafkademo.oauth2;

import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.Map;

public class SecurityContextUtil {

    static Duration DEFAULT_MAX_CLOCK_SKEW;

    static {
        DEFAULT_MAX_CLOCK_SKEW = Duration.of(5L, ChronoUnit.SECONDS);
    }

    public static SecurityContext securityContext(){
        return SecurityContextHolder.getContext();
    }

    public static Map<String, Object> getClaims(){
        return ((Jwt) securityContext().getAuthentication().getPrincipal()).getClaims();
    }

}
