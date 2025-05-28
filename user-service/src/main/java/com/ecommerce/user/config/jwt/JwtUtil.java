package com.ecommerce.user.config.jwt;

import com.ecommerce.user.model.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Classe utilitária para operações relacionadas a JWT.
 * Centraliza a lógica de geração e validação de tokens.
 */
@Component
public class JwtUtil {

    private final JwtProperties jwtProperties;

    public JwtUtil(JwtProperties jwtProperties) {
        this.jwtProperties = jwtProperties;
    }

    /**
     * Gera um token JWT para um usuário.
     * 
     * @param user O usuário para o qual gerar o token
     * @return O token JWT gerado
     */
    public String generateToken(User user) {
        Key key = Keys.hmacShaKeyFor(jwtProperties.getSecret().getBytes());
        
        // Extrair nomes de todas as roles
        List<String> roles = user.getRoles().stream()
                .map(role -> role.getName())
                .collect(Collectors.toList());
        
        // Extrair nomes de todas as permissões
        List<String> permissions = user.getRoles().stream()
                .flatMap(role -> role.getPermissions().stream())
                .map(permission -> permission.getName())
                .distinct()
                .collect(Collectors.toList());
        
        return Jwts.builder()
                .setSubject(user.getEmail())
                .claim("id", user.getId())
                .claim("name", user.getName())
                .claim("roles", roles)
                .claim("permissions", permissions)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + jwtProperties.getExpirationMs()))
                .signWith(key)
                .compact();
    }

    /**
     * Valida e extrai as claims de um token JWT.
     * 
     * @param token O token JWT a ser validado
     * @return As claims do token se válido, ou null se inválido
     */
    public Claims validateTokenAndGetClaims(String token) {
        try {
            return Jwts.parser()
                    .setSigningKey(jwtProperties.getSecret().getBytes())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Extrai o email do usuário (subject) de um token JWT.
     * 
     * @param token O token JWT
     * @return O email do usuário se o token for válido, ou null caso contrário
     */
    public String getEmailFromToken(String token) {
        Claims claims = validateTokenAndGetClaims(token);
        return claims != null ? claims.getSubject() : null;
    }
} 