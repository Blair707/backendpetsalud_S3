package com.petsalud.backendpetsalud.controller;

import com.petsalud.backendpetsalud.dto.LoginRequest;
import com.petsalud.backendpetsalud.dto.LoginResponse;
import com.petsalud.backendpetsalud.security.JwtUtil;
import com.petsalud.backendpetsalud.security.LoginAttemptService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private static final Logger log = LoggerFactory.getLogger(AuthController.class);

    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtil;
    private final LoginAttemptService loginAttempts;
    private final long expiracionMs;

    public AuthController(AuthenticationManager authenticationManager, JwtUtil jwtUtil,
                          LoginAttemptService loginAttempts,
                          @Value("${jwt.expiration-ms}") long expiracionMs) {
        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;
        this.loginAttempts = loginAttempts;
        this.expiracionMs = expiracionMs;
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest req, HttpServletRequest http) {
        String ip = http.getRemoteAddr();

        if (loginAttempts.estaBloqueado(req.email())) {
            log.warn("SEGURIDAD login bloqueado temporalmente email={} ip={}", req.email(), ip);
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                    .body(Map.of("error", "Demasiados intentos fallidos. Intente más tarde."));
        }
        try {
            Authentication auth = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(req.email(), req.password()));
            String rol = auth.getAuthorities().iterator().next().getAuthority();
            loginAttempts.registrarExito(req.email());
            log.info("SEGURIDAD login exitoso email={} rol={} ip={}", req.email(), rol, ip);
            return ResponseEntity.ok(new LoginResponse(jwtUtil.generarToken(req.email(), rol), "Bearer", rol, expiracionMs));
        } catch (AuthenticationException e) {
            loginAttempts.registrarFallo(req.email());
            log.warn("SEGURIDAD login fallido email={} ip={}", req.email(), ip);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "Credenciales inválidas"));
        }
    }
}
