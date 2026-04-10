package com.programacion4.unidad5ej7.auth.dtos.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/*
	Record: clase inmutable ultra compacta pesada para el transporte de datos. Casos de uso:
		- Es solo datos.
		- **Es inmutable**.
		- Es i/o del controller.
	No permite settear atributos (dto.setUsername() -> no existe).
	dto.getUsername() -> pasa a ser -> dto.username()

	DTOs usando class sirven cuando:
		- **Necesitás mutabilidad**.
		- Tiene lógica interna (ej: dto.setAlgo()).
		- Es una entidad JPA.
 */

public record LoginRequestDto(
		@NotBlank(message = "El usuario es obligatorio") 
		@Size(max = 64) 
		String username,

		@NotBlank(message = "La contraseña es obligatoria") 
		@Size(max = 128) 
		String password
	) {
}
