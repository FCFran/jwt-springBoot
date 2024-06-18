package com.dusseldorf.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.constraints.NotNull;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Service;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * spring no puede entender que esto es un filtro por eso
 * extendemos de OncePerRequestFilter -> par convertir esta clase en un filtro
 */
@Service
@RequiredArgsConstructor
public class JwtFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;
    @Override
    protected void doFilterInternal( @NotNull HttpServletRequest request,
                                     @NotNull HttpServletResponse response,
                                     @NotNull FilterChain filterChain
    ) throws ServletException, IOException {
        //para las rutas permitidas si autenticaticacion tenemos que realizar este chequeo
        if (request.getServletPath().contains("/api/v1/auth")) {
            filterChain.doFilter(request, response); // pasamos la solicitud y la respuesta
            return;
        }

        final String authHeaders = request.getHeader(HttpHeaders.AUTHORIZATION); // obtener encabezado
        final String jwt;
        final String userMail;

        if (authHeaders == null || !authHeaders.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        jwt = authHeaders.substring(7);
        userMail= jwtService.extractUsername(jwt); // extraer el nombre de usuario del jwt
        //comprobar si el usuario no esta authentificado si el igual a null desde el contexto de seguridad -> SecurityContextHolder
        if (userMail != null && SecurityContextHolder.getContext().getAuthentication() == null){
            UserDetails userDetails = userDetailsService.loadUserByUsername(userMail);
            // si el token es valido
            if(jwtService.isTokenValid(jwt, userDetails)){
                //para el inicio de sesion
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities()

                );
                //configurar los detalles establecidos en token de authenticacion
                authToken.setDetails(
                        //construir detalles de nuestra solicitud
                        new WebAuthenticationDetailsSource().buildDetails(request)
                );

                //actualizar el titular del contexto
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }
        filterChain.doFilter(request, response);
    }

}
