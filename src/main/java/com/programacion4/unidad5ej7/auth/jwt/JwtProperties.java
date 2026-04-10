package com.programacion4.unidad5ej7.auth.jwt;

import org.springframework.boot.context.properties.ConfigurationProperties;

/*
    Mapeo de config JWT con archivo externo. Evita hardcodear datos sensibles
 */
@ConfigurationProperties(prefix = "app.jwt")
public record JwtProperties(
    String secret,  // firma JWT (tokens válidos)
    long expirationMs,  // duración de token
    long refreshExpirationMs, // duración refreshToken
    String algorithm    // algoritmo de firma (generación/verificación de token)
) {
}
