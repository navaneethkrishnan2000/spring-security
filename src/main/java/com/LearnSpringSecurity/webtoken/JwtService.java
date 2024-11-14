package com.LearnSpringSecurity.webtoken;

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

    private static final String SECRET = "7853E673F4E2CBDFA0A65102FDB5523A07361483B66AEC742CACE2B4A525B19DC289AF9497B44CC140936BA13851658FE2503AEF62241759C442885EA3910A27";
    private static final long EXPIRATION_TIME = TimeUnit.MINUTES.toMillis(30);
    public String generateToken(UserDetails userDetails) {
        Map<String, String> claims = new HashMap<>();
        claims.put("issue" , "");
        return Jwts.builder()
                .claims(claims)
                .subject(userDetails.getUsername())
                .issuedAt(Date.from(Instant.now()))
                .expiration(Date.from(Instant.now().plusMillis(EXPIRATION_TIME)))
                .signWith(generateKey())
                .compact();
    }

    private SecretKey generateKey() {
        byte[] decodedKey = Base64.getDecoder().decode(SECRET);
        return Keys.hmacShaKeyFor(decodedKey);
    }

}
