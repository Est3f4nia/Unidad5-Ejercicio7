package com.programacion4.unidad5ej7.auth.controllers;

import com.programacion4.unidad5ej7.auth.dtos.request.LoginRequestDto;
import com.programacion4.unidad5ej7.auth.dtos.request.RefreshRequestDto;
import com.programacion4.unidad5ej7.auth.dtos.request.RegisterRequestDto;
import com.programacion4.unidad5ej7.auth.dtos.response.AuthResponseDto;
import com.programacion4.unidad5ej7.auth.dtos.response.RefreshResponseDto;
import com.programacion4.unidad5ej7.auth.services.interfaces.IAuthService;
import com.programacion4.unidad5ej7.config.BaseResponse;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import lombok.AllArgsConstructor;

/*
	->  Define endpoints que no requieren autenticación (/register y /login).
	Controller normal solo que aplicado a autenticación y validación.
 */

@RestController
@RequestMapping("/auth")
@AllArgsConstructor
public class AuthController {
	private final IAuthService authService;

	@PostMapping("/register")
	public ResponseEntity<BaseResponse<Void>> register(@Valid @RequestBody RegisterRequestDto request) {
		authService.register(request);
		return ResponseEntity.status(HttpStatus.CREATED)
				.body(BaseResponse.ok(null, "Usuario registrado correctamente"));
	}

	@PostMapping("/login")
	public ResponseEntity<BaseResponse<AuthResponseDto>> login(@Valid @RequestBody LoginRequestDto request) {
		AuthResponseDto body = authService.login(request);
		return ResponseEntity.ok(BaseResponse.ok(body, "Autenticación correcta"));
	}

	@PostMapping("/refresh")
	public ResponseEntity<BaseResponse<RefreshResponseDto>> refresh(@Valid @RequestBody RefreshRequestDto request) {
		RefreshResponseDto body = authService.refresh(request);
		return ResponseEntity.ok(BaseResponse.ok(body, "Token renovado correctamente"));
	}
}
