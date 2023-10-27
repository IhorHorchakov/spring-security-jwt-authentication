package com.example.rest;

import com.example.rest.request.LoginRequest;
import com.example.security.TokenService;
import com.example.model.UserDetailWrapper;
import com.example.service.UserDetailsSecurityService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Slf4j
public class AuthenticationController {
    private final TokenService tokenService;
    private final AuthenticationManager authManager;
    private final UserDetailsSecurityService userDetailsSecurityService;

    public AuthenticationController(TokenService tokenService, AuthenticationManager authManager, UserDetailsSecurityService userDetailsSecurityService) {
        this.tokenService = tokenService;
        this.authManager = authManager;
        this.userDetailsSecurityService = userDetailsSecurityService;
    }

    @PostMapping("/login")
    public LoginResponse login(@RequestBody LoginRequest request) {
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword());
        authManager.authenticate(authenticationToken);

        UserDetailWrapper userDetailWrapper = (UserDetailWrapper) userDetailsSecurityService.loadUserByUsername(request.getUsername());
        String accessToken = tokenService.generateAccessToken(userDetailWrapper);
        String refreshToken = tokenService.generateRefreshToken(userDetailWrapper);

        return new LoginResponse(accessToken, refreshToken);
    }

    @GetMapping("/token/refresh")
    public RefreshTokenResponse refreshToken(HttpServletRequest request) {
        String authenticationHeader = request.getHeader("Authorization");

        String username = tokenService.parseToken(authenticationHeader.substring(7));
        UserDetailWrapper user = (UserDetailWrapper) userDetailsSecurityService.loadUserByUsername(username);
        String accessToken = tokenService.generateAccessToken(user);
        String refreshToken = tokenService.generateRefreshToken(user);

        return new RefreshTokenResponse(accessToken, refreshToken);
    }

    record RefreshTokenResponse(String accessJwt, String refreshJwt) {
    }

    record LoginResponse(String accessJwt, String refreshJwt) {
    }

}