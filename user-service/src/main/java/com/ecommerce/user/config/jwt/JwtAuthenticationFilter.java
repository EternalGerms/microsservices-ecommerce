package com.ecommerce.user.config.jwt;

import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.lang.NonNull;
import com.ecommerce.user.model.User;
import com.ecommerce.user.service.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationFilter.class);
    
    private final JwtUtil jwtUtil;
    private final UserService userService;

    public JwtAuthenticationFilter(UserService userService, JwtUtil jwtUtil) {
        this.userService = userService;
        this.jwtUtil = jwtUtil;
    }

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response, @NonNull FilterChain filterChain)
            throws ServletException, IOException {
        String authHeader = request.getHeader("Authorization");
        
        logger.debug("Request URI: {}", request.getRequestURI());
        
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);
            Claims claims = jwtUtil.validateTokenAndGetClaims(token);
            
            if (claims != null) {
                String email = claims.getSubject();
                
                if (email != null) {
                    User user = userService.findByEmail(email);
                    
                    if (user != null && user.isActive()) {
                        // Obter permissões do usuário
                        List<SimpleGrantedAuthority> authorities = new ArrayList<>();
                        
                        // Adicionar roles como authorities
                        authorities.addAll(user.getRoles().stream()
                                .map(role -> {
                                    String roleName = role.getName();
                                    String authorityName = roleName.startsWith("ROLE_") ? 
                                        roleName : "ROLE_" + roleName;
                                    logger.debug("Adding role authority: {}", authorityName);
                                    return new SimpleGrantedAuthority(authorityName);
                                })
                                .collect(Collectors.toList()));
                        
                        // Adicionar permissões como authorities
                        authorities.addAll(user.getRoles().stream()
                                .flatMap(role -> role.getPermissions().stream())
                                .map(permission -> {
                                    logger.debug("Adding permission authority: {}", permission.getName());
                                    return new SimpleGrantedAuthority(permission.getName());
                                })
                                .collect(Collectors.toList()));
                        
                        logger.debug("User authorities: {}", authorities);
                        
                        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                                email, null, authorities);
                        authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                        SecurityContextHolder.getContext().setAuthentication(authentication);
                        logger.debug("Authentication set for user: {}", email);
                    } else {
                        logger.warn("User not found or inactive: {}", email);
                    }
                }
            } else {
                // Token inválido ou expirado
                logger.warn("Invalid or expired token");
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                return;
            }
        } else {
            logger.debug("No Authorization header or not a Bearer token");
        }
        filterChain.doFilter(request, response);
    }
} 