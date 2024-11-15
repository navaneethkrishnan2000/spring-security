package com.LearnSpringSecurity.webtoken;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

@Service
public class JwtService {

    private static final String SECRET = "E19A45EAF080E008B28557A5250B86207776FFB8A9FE897FBA13FB2EBB443037E069104CDD505777C4705E0CD01EFA1C7798211E0555E0516082BE42D95E1C3D";
    private static final long EXPIRATION_TIME = TimeUnit.MINUTES.toMillis(60);

    public String generateToken(UserDetails userDetails) {
        Map<String, String> claims = new HashMap<>();
//        claims.put("issue" , "https://secure.genuinecoder.com");
//        claims.put("name", "bruce");
        System.out.println("Token Generated");
        return Jwts.builder()
                .claims(claims) // used to add extra data to the payload to generate token, these values will be stored in the token
                .subject(userDetails.getUsername())
                .issuedAt(Date.from(Instant.now()))
                .expiration(Date.from(Instant.now().plusMillis(EXPIRATION_TIME)))
                .signWith(generateKey()) // to set the key we use the signWith
                .compact(); // to convert the generated key as string
    }

    private SecretKey generateKey() {
        byte[] decodedKey = Base64.getDecoder().decode(SECRET);
        return Keys.hmacShaKeyFor(decodedKey);
    }/* we have the key in the encoded format in the variable SECRET,
     We have to convert it into a secret key object, that can be done by using base 64 then decoded key is stored in the byte array
     now using decodedKey we can generate the secret key */

    public String extractUsername(String jwt) {
        Claims claims = getClaims(jwt);
        return claims.getSubject();
    }

    private Claims getClaims(String jwt) {
        Claims claims = Jwts.parser()
                .verifyWith(generateKey())
                .build()
                .parseSignedClaims(jwt)
                .getPayload();
        return claims;
    }

    // TO get the expiration-time we need the claims object
    // then we have to make sure that the token is not expired, for that we need to get the expiration-time after the token is created
    // this is how we are validating the token
    public boolean isTokenValid(String jwt) {
        Claims claims = getClaims(jwt);
        return claims.getExpiration().after(Date.from(Instant.now()));
    }
}
