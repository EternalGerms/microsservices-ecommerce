package com.ecommerce.user.config;

import com.ecommerce.user.config.jwt.JwtAuthenticationFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.context.annotation.Configuration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.lang.NonNull;
import java.io.IOException;

@Configuration
@EnableMethodSecurity(prePostEnabled = true)  // Re-enable method-level security
@EnableConfigurationProperties
public class SecurityConfig {
    private static final Logger logger = LoggerFactory.getLogger(SecurityConfig.class);
    
    @Bean
    SecurityFilterChain filterChain(HttpSecurity http, JwtAuthenticationFilter jwtFilter) throws Exception {
        logger.debug("Configuring SecurityFilterChain");
        
        http
            .csrf(csrf -> csrf.disable())
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/auth/login", "/auth/register", "/h2-console/**").permitAll()
                .requestMatchers("/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated()
            );
        http.headers(headers -> headers.frameOptions(frame -> frame.disable())); // H2 console
        http.addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);
        http.addFilterBefore(new RequestLoggingFilter(), UsernamePasswordAuthenticationFilter.class);
        
        return http.build();
    }

    @Bean
    AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }
    
    @Component
    public static class RequestLoggingFilter extends OncePerRequestFilter {
        private final Logger logger = LoggerFactory.getLogger(RequestLoggingFilter.class);
        
        @Override
        protected void doFilterInternal(
                @NonNull HttpServletRequest request,
                @NonNull HttpServletResponse response,
                @NonNull FilterChain filterChain) throws ServletException, IOException {
            
            logger.info("Request: {} {}", request.getMethod(), request.getRequestURI());
            
            if (request.getRequestURI().contains("/admin/users/") && "PUT".equals(request.getMethod())) {
                logger.info("Admin PUT request: Authorization header present: {}", 
                        request.getHeader("Authorization") != null);
                
                // Log request body for role updates
                if (request.getRequestURI().contains("/roles")) {
                    try {
                        String body = request.getReader().lines()
                                .collect(java.util.stream.Collectors.joining(System.lineSeparator()));
                        logger.info("Role update body: {}", body);
                    } catch (Exception e) {
                        logger.error("Error reading request body", e);
                    }
                }
            }
            
            filterChain.doFilter(request, response);
            
            logger.info("Response: {} {}: {}", 
                    request.getMethod(), request.getRequestURI(), response.getStatus());
        }
    }
} 