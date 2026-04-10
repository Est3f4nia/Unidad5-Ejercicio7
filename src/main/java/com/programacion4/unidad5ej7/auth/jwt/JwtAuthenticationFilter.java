package com.programacion4.unidad5ej7.auth.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

import lombok.AllArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
@AllArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {	// ejecución por cada request que entra
	private static final String BEARER_PREFIX = "Bearer ";
	private final JwtService jwtService;
	private final UserDetailsService userDetailsService;

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		// Ignora si la request es a paths públicos
		if (shouldNotProcess(request)) {
			filterChain.doFilter(request, response);
			return;
		}

		// Para no pisar autenticación existente
		if (alreadyHasUserAuthentication()) {
			filterChain.doFilter(request, response);
			return;
		}

		// Obtiene header de autenticación
		String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
		// Si no hay token, no hace nada
		if (authHeader == null || !authHeader.startsWith(BEARER_PREFIX)) {
			filterChain.doFilter(request, response);
			return;
		}

		// Extrae token del header
		String token = authHeader.substring(BEARER_PREFIX.length()).trim();
		if (token.isEmpty()) {
			filterChain.doFilter(request, response);
			return;
		}

		// Validación de token (firma, expiration, claims)
		jwtService.parseValidClaims(token).ifPresent(claims -> {
			String username = claims.getSubject();	// saca user
			if (username == null || username.isBlank()) {
				return;
			}
			try {
				UserDetails userDetails = userDetailsService.loadUserByUsername(username);	// validación contra DB: prioriza seguridad sobre perfonmance (más queries)
				UsernamePasswordAuthenticationToken authentication =
						new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());	// crea un usuario autenticado con permisos custom
				authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
				SecurityContextHolder.getContext().setAuthentication(authentication);	// define contexto global (autenticado o no)
			} catch (UsernameNotFoundException ignored) {
				// Token válido pero usuario ya no existe: no rellenar el contexto.
			}
		});

		filterChain.doFilter(request, response);	// continua el flujo de la request.
	}

	/** Rutas públicas: no validar JWT ni cargar usuario (menos trabajo y sin consultas innecesarias). */
	private boolean shouldNotProcess(HttpServletRequest request) {
		String path = request.getServletPath();
		return path.startsWith("/auth/")
				|| path.startsWith("/insumos/")
				|| path.startsWith("/h2-console");
	}

	// Don't override valid autentication
	private boolean alreadyHasUserAuthentication() {
		Authentication auth = SecurityContextHolder.getContext().getAuthentication();
		return auth != null && auth.getPrincipal() instanceof UserDetails;
	}
}
