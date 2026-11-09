package com.petsalud.backendpetsalud.security;

import com.petsalud.backendpetsalud.repository.MascotaRepository;
import com.petsalud.backendpetsalud.repository.NotificacionRepository;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

@Component("acceso")
public class AccesoService {

    private final MascotaRepository mascotaRepository;
    private final NotificacionRepository notificacionRepository;

    public AccesoService(MascotaRepository mascotaRepository, NotificacionRepository notificacionRepository) {
        this.mascotaRepository = mascotaRepository;
        this.notificacionRepository = notificacionRepository;
    }

    public boolean esUsuario(Long usuarioId) {
        Authentication a = SecurityContextHolder.getContext().getAuthentication();
        return a != null && a.getPrincipal() instanceof UsuarioDetails u && u.getId().equals(usuarioId);
    }

    public boolean esDuenoDeMascota(Long mascotaId) {
        return mascotaRepository.findById(mascotaId)
                .map(m -> m.getPropietario() != null && esUsuario(m.getPropietario().getId()))
                .orElse(false);
    }

    public boolean esDuenoDeNotificacion(Long notificacionId) {
        return notificacionRepository.findById(notificacionId)
                .map(n -> n.getUsuario() != null && esUsuario(n.getUsuario().getId()))
                .orElse(false);
    }
}
