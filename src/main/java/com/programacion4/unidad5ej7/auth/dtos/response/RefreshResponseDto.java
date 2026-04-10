package com.programacion4.unidad5ej7.auth.dtos.response;

public record RefreshResponseDto (
        String accessToken,
        String tokenType,
        long expiresIn
) {}