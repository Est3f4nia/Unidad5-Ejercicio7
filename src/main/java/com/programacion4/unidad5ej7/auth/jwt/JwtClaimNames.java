package com.programacion4.unidad5ej7.auth.jwt;

/*
	Centralización de contrato JWT: consistencia en todo el sistema
 */

public final class JwtClaimNames {
	public static final String ROLES = "roles";

	// Evita instanciación (new JwtClaimNames())
	private JwtClaimNames() {}
}
