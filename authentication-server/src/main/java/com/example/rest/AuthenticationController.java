package com.example.rest;

import com.example.rest.request.LoginRequest;
import com.example.rest.response.AuthenticationResponse;
import com.example.rest.response.RefreshTokenResponse;
import com.example.service.TokenService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Slf4j
public class AuthenticationController {
    private final TokenService tokenService;
    private final AuthenticationManager authManager;
    private final UserDetailsService userDetailsService;

    public AuthenticationController(TokenService tokenService, AuthenticationManager authManager, UserDetailsService userDetailsService) {
        this.tokenService = tokenService;
        this.authManager = authManager;
        this.userDetailsService = userDetailsService;
    }

    @PostMapping("/authenticate")
    public AuthenticationResponse login(@RequestBody LoginRequest request) {
        Authentication authenticationToken = new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword());

        // throws AuthenticationException if authentication fails
        authManager.authenticate(authenticationToken);

        UserDetails userDetails = userDetailsService.loadUserByUsername(request.getUsername());
        String accessToken = tokenService.generateAccessToken(userDetails);
        String refreshToken = tokenService.generateRefreshToken(userDetails);
        return new AuthenticationResponse(accessToken, refreshToken);
    }

    @GetMapping("/token/refresh")
    public RefreshTokenResponse refreshToken(HttpServletRequest request) {
        String username = tokenService.getTokenUsernameFromRequest(request);
        UserDetails userDetails = userDetailsService.loadUserByUsername(username);
        String accessToken = tokenService.generateAccessToken(userDetails);
        String refreshToken = tokenService.generateRefreshToken(userDetails);
        return new RefreshTokenResponse(accessToken, refreshToken);
    }

}