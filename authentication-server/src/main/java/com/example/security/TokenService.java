package com.example.security;

import com.example.model.UserDetailsModel;
import com.nimbusds.jwt.SignedJWT;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Component;

import java.text.ParseException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.stream.Collectors;

@Component
public class TokenService {
    private final Integer ACCESS_TOKEN_LIFETIME_IN_MINUTES = 30;
    private final Integer REFRESH_TOKEN_LIFETIME_IN_MINUTES = 5;
    @Autowired
    private JwtEncoder jwtEncoder;

    public String generateAccessToken(UserDetailsModel userDetailWrapper) {
       return generateJwt(userDetailWrapper, ACCESS_TOKEN_LIFETIME_IN_MINUTES);
    }

    public String generateRefreshToken(UserDetailsModel userDetailWrapper) {
        return generateJwt(userDetailWrapper, REFRESH_TOKEN_LIFETIME_IN_MINUTES);
    }

    private String generateJwt(UserDetailsModel userDetailWrapper, Integer lifetime) {
        Instant now = Instant.now();
        String scope = userDetailWrapper.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(" "));

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("self")
                .issuedAt(now)
                .expiresAt(now.plus(lifetime, ChronoUnit.MINUTES))
                .subject(userDetailWrapper.getUsername())
                .claim("scope", scope)
                .build();
        return jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
    }

    public String getTokenUsernameFromRequest(HttpServletRequest request) {
        try {
            String authenticationHeader = request.getHeader("Authorization");
            String rawJwt = authenticationHeader.substring(7);
            SignedJWT decodedJwt = SignedJWT.parse(rawJwt);
            String subject = decodedJwt.getJWTClaimsSet().getSubject();
            return subject;
        } catch (ParseException e) {
            e.printStackTrace();
        }
        return null;
    }
}
