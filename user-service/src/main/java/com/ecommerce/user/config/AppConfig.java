package com.ecommerce.user.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * Configuração principal da aplicação que habilita recursos como
 * carregamento de propriedades de configuração de arquivos externos.
 */
@Configuration
@EnableConfigurationProperties
public class AppConfig {
    // Esta classe habilita a detecção automática de classes com @ConfigurationProperties
} 