package com.jwt.security.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {
    //the key is for the signature of the jwt
    private static final String SECRET_KEY = "357538782F413F4428472B4B6250655367566B59703373367639792442264529";

    //extracts the username of the authentication: email
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public <T> T extractClaim(String token, Function<Claims,T> claimsResolver){
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    public String generateToken(UserDetails userDetails){
        return generateToken(new HashMap<>(), userDetails);
    }

    public String generateToken(
            Map<String, Object> extraClaims,
            UserDetails userDetails
    ){
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis()+1000 * 60 * 24 )) //24h + 1000 ms
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }


    //hadi ki zedt userId to claims bssh i found a better sol: searching b email (extracted mn jwt) b restTemplate f other services
    /*public String generateToken(
            Map<String, Object> extraClaims,
            UserDetails userDetails,
            Long userId
    ){
        //added userId with claims so it can be retrieved later on its own
        Map<String, Object> claims = new HashMap<>();
        claims.put("userId", userId);
        claims.putAll(extraClaims);

        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis()+1000 * 60 * 24 )) //24h + 1000 ms
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }*/

    //newly added cuz i added userID to claims
    /*public Long extractUserId(String token) {
        return extractClaim(token, claims -> claims.get("userId", Long.class));
    }*/

    public boolean isTokenValid(String token, UserDetails userDetails){
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }


    private Claims extractAllClaims(String token){ //signin key: to create the signature of jwt to ensure that the token hasn't been changed
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInKey()) //setSignInKey(Key key)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }



    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }

}