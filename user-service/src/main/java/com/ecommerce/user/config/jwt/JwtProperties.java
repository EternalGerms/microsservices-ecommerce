package com.ecommerce.user.config.jwt;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * Configurações relacionadas ao JWT carregadas a partir de properties ou variáveis de ambiente.
 * Isso permite armazenar de forma segura configurações sensíveis fora do código-fonte.
 */
@Component
@ConfigurationProperties(prefix = "jwt")
public class JwtProperties {
    
    /**
     * Secret key usada para assinar e validar tokens JWT.
     * Padrão temporário para desenvolvimento local apenas.
     * Em produção, deve ser definido por variável de ambiente JWT_SECRET.
     */
    private String secret = "default_development_secret_do_not_use_in_production";
    
    /**
     * Tempo de expiração do token JWT em milissegundos.
     * Padrão: 24 horas (86400000 ms)
     */
    private long expirationMs = 86400000; // 24 horas
    
    public String getSecret() {
        // Prioriza a variável de ambiente JWT_SECRET, se disponível
        String envSecret = System.getenv("JWT_SECRET");
        return (envSecret != null && !envSecret.isEmpty()) ? envSecret : secret;
    }
    
    public void setSecret(String secret) {
        this.secret = secret;
    }
    
    public long getExpirationMs() {
        // Prioriza a variável de ambiente JWT_EXPIRATION_MS, se disponível
        String envExpiration = System.getenv("JWT_EXPIRATION_MS");
        return (envExpiration != null && !envExpiration.isEmpty()) 
            ? Long.parseLong(envExpiration) 
            : expirationMs;
    }
    
    public void setExpirationMs(long expirationMs) {
        this.expirationMs = expirationMs;
    }
} 