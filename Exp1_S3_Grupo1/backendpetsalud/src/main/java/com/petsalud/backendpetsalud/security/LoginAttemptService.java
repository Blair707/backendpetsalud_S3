package com.petsalud.backendpetsalud.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class LoginAttemptService {

    private record Intento(int cantidad, Instant bloqueadoHasta) {}

    private final Map<String, Intento> intentos = new ConcurrentHashMap<>();
    private final int maxIntentos;
    private final Duration bloqueo;

    public LoginAttemptService(@Value("${seguridad.max-intentos-fallidos}") int maxIntentos,
                               @Value("${seguridad.bloqueo-minutos}") long bloqueoMinutos) {
        this.maxIntentos = maxIntentos;
        this.bloqueo = Duration.ofMinutes(bloqueoMinutos);
    }

    public void registrarFallo(String email) {
        intentos.merge(email.toLowerCase(), new Intento(1, null), (actual, nuevo) -> {
            int n = actual.cantidad() + 1;
            return new Intento(n, n >= maxIntentos ? Instant.now().plus(bloqueo) : null);
        });
    }

    public void registrarExito(String email) {
        intentos.remove(email.toLowerCase());
    }

    public boolean estaBloqueado(String email) {
        Intento i = intentos.get(email.toLowerCase());
        if (i == null || i.bloqueadoHasta() == null) return false;
        if (Instant.now().isAfter(i.bloqueadoHasta())) {
            intentos.remove(email.toLowerCase());
            return false;
        }
        return true;
    }
}
