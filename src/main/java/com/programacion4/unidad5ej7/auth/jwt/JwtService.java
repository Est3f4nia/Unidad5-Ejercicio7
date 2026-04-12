package com.programacion4.unidad5ej7.auth.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import jakarta.annotation.PostConstruct;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import javax.crypto.SecretKey;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import io.jsonwebtoken.security.Keys;

/*
	Generación, validación y lectura de tokens
 */

@Service
@RequiredArgsConstructor
public class JwtService {
	private static final int MIN_SECRET_BYTES = 32;
	private final JwtProperties properties;
	private SecretKey signingKey;

	@PostConstruct
	void initSigningKey() {	// ejecución única, al levantar app
		// comprobación de algoritmo
		if (!"HS256".equalsIgnoreCase(properties.algorithm())) {
			throw new IllegalStateException("Solo está soportado el algoritmo HS256 (app.jwt.algorithm)");
		}

		// generación de firma a partir de secret
		byte[] keyBytes = properties.secret().getBytes(StandardCharsets.UTF_8);	// secret como plaintext (debe venir de entorno seguro o tener entropía (aleatoriedad) alta)
		if (keyBytes.length < MIN_SECRET_BYTES) {
			throw new IllegalStateException(
					"app.jwt.secret debe tener al menos " + MIN_SECRET_BYTES + " bytes en UTF-8 para HS256");
		}

		signingKey = Keys.hmacShaKeyFor(keyBytes);	// convierte el secret en clave válida
	}

	// generación de tokens de acceso
	public String generateToken(String username, Collection<String> roles) {
		Instant now = Instant.now();
		Instant expiry = now.plusMillis(properties.expirationMs());
		return Jwts.builder()
				.subject(username)
				.claim(JwtClaimNames.ROLES, List.copyOf(roles))
				.issuedAt(Date.from(now))
				.expiration(Date.from(expiry))
				.signWith(signingKey, Jwts.SIG.HS256)
				.compact();
	}

	public String generateRefreshToken(String username) {
		Instant now = Instant.now();
		Instant expiry = now.plusMillis(properties.refreshExpirationMs());
		return Jwts.builder()
				.subject(username)
				.issuedAt(Date.from(now))
				.expiration(Date.from(expiry))
				.signWith(signingKey, Jwts.SIG.HS256)
				.compact();
	}

	// validación de firma, expiración y estructura del token
	public Optional<Claims> parseValidClaims(String token) {
		if (token == null || token.isBlank()) {
			return Optional.empty();
		}

		try {
			return Optional.of(
					Jwts.parser()
							.verifyWith(signingKey)	// verifica firma
							.build()
							.parseSignedClaims(token)
							.getPayload());
		} catch (JwtException ignored) {
			return Optional.empty();
		}
	}

	public Optional<String> extractUsername(String token) {
		return parseValidClaims(token).map(Claims::getSubject);
	}

	public List<String> extractRoles(Claims claims) {
		Object raw = claims.get(JwtClaimNames.ROLES);
		if (raw instanceof List<?> list) {
			return list.stream().map(Object::toString).toList();
		}
		return List.of();
	}
}
