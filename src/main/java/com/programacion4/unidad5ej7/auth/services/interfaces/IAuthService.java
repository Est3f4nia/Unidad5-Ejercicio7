package com.programacion4.unidad5ej7.auth.services.interfaces;

import com.programacion4.unidad5ej7.auth.dtos.request.LoginRequestDto;
import com.programacion4.unidad5ej7.auth.dtos.request.RefreshRequestDto;
import com.programacion4.unidad5ej7.auth.dtos.request.RegisterRequestDto;
import com.programacion4.unidad5ej7.auth.dtos.response.AuthResponseDto;
import com.programacion4.unidad5ej7.auth.dtos.response.RefreshResponseDto;


public interface IAuthService {
    void register(RegisterRequestDto request);
    AuthResponseDto login(LoginRequestDto request);
    RefreshResponseDto refresh(RefreshRequestDto request);
}
