package com.dusseldorf.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {
    @Value("${application.security.jwt.secret-key}")
    private String secretKey;

    @Value("${application.security.jwt.expiration}")
    private long jwtExpiration;

    /*------------------------Método para extraer el username----------------------------------*/
    public String extractUsername(String token){
        return extractCalims(token, Claims::getSubject);
    }

    private <T> T extractCalims(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    //metodo de reclamos este devolvera una lista de claims
    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSingInKey()) // clase de firma que usamos
                .build()
                .parseClaimsJwt(token)
                .getBody(); // obtenemos el cuerpo
    }

    /*------------------------Fin Método para extraer el username------------------------------*/



    /*-----------------------Métodos para generar el token--------------------------------------*/

    /**
     * Método que genera el token -> se utiliza cuando solo enviamos el user details, sin ningun claims(reclamos)
     *
     * @param userDetails
     * @return token
     */
    public String generateToken(UserDetails userDetails){
        return generateToken(new HashMap<>(),userDetails);
    }

    /**
     * Método que genera el token -> se utiliza cuando enviamos el UserDetails y los claims com mayor informacion en
     * el playload
     *
     *
     * @param userDetails
     * @return token
     */
    public String generateToken(Map<String, Object> claims, UserDetails userDetails) {
        return buildToken(claims, userDetails, jwtExpiration);
    }

    private String buildToken(Map<String, Object> extraClaims,
                              UserDetails userDetails,
                              long jwtExpiration) {

        var authorities = userDetails.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .toList();

        return Jwts.builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis())) //fecha de creación del token
                .setExpiration(new Date(System.currentTimeMillis() + jwtExpiration))
                .claim("authorities", authorities) // establecer algunas reclamaciones extras
                .signWith(getSingInKey()) //firma del token
                .compact(); //generar el token
    }

    /* metodo para para obtener la clave codificada*/
    /**
     * decodificamos jwtSecret en una matriz de bytes . A continuación, invocamos hmacShaKeyFor()  que acepta keyBytes
     * como parámetro en la instancia de Keys. Esto genera una clave secreta basada en el algoritmo HMAC.
     * @return clave codificada
     *
     */
    //https://auth0.com/es/learn/json-web-tokens,
    //https://www.baeldung.com/spring-security-sign-jwt-token
    private Key getSingInKey() {
        byte[] keyBytes = Decoders.BASE64URL.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    /*-----------------------Fin Métodos para generar el token----------------------------------*/



    /*----------------------------Métodos de validacion del token-------------------------------*/
    public boolean isTokenValid(String token, UserDetails userDetails){
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractCalims(token,Claims::getExpiration);
    }

    /*--------------------------Fin Métodos de validacion del token-----------------------------*/

}
