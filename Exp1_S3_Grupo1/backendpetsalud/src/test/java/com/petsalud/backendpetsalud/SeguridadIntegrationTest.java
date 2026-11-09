package com.petsalud.backendpetsalud;

import com.petsalud.backendpetsalud.entity.Rol;
import com.petsalud.backendpetsalud.entity.Usuario;
import com.petsalud.backendpetsalud.repository.UsuarioRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
class SeguridadIntegrationTest {

    @Autowired MockMvc mvc;
    @Autowired UsuarioRepository repo;
    @Autowired PasswordEncoder encoder;

    @BeforeEach
    void datos() {
        repo.deleteAll();
        crear("cliente@petsalud.cl", Rol.CLIENTE);
        crear("empleado@petsalud.cl", Rol.EMPLEADO);
        crear("gerente@petsalud.cl", Rol.GERENTE);
    }

    private void crear(String email, Rol rol) {
        repo.save(Usuario.builder().email(email).password(encoder.encode("Clave1234")).rol(rol).nombre("T").build());
    }

    private String login(String email, String pass) throws Exception {
        MvcResult r = mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
                .content("{\"email\":\"" + email + "\",\"password\":\"" + pass + "\"}")).andReturn();
        String body = r.getResponse().getContentAsString();
        int i = body.indexOf("\"token\":\"");
        return i < 0 ? null : body.substring(i + 9, body.indexOf('"', i + 9));
    }

    private String bearer(String email) throws Exception { return "Bearer " + login(email, "Clave1234"); }

    @Test void sinTokenRetorna401() throws Exception {
        mvc.perform(get("/api/productos")).andExpect(status().isUnauthorized());
    }

    @Test void loginCorrectoEntregaToken() throws Exception {
        assertNotNull(login("cliente@petsalud.cl", "Clave1234"));
    }

    @Test void loginIncorrectoRetorna401() throws Exception {
        mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
                .content("{\"email\":\"cliente@petsalud.cl\",\"password\":\"mala\"}")).andExpect(status().isUnauthorized());
    }

    @Test void tokenAlteradoRetorna401() throws Exception {
        mvc.perform(get("/api/productos").header("Authorization", bearer("cliente@petsalud.cl") + "x"))
                .andExpect(status().isUnauthorized());
    }

    @Test void clienteListaProductosPeroNoLosCrea() throws Exception {
        String t = bearer("cliente@petsalud.cl");
        mvc.perform(get("/api/productos").header("Authorization", t)).andExpect(status().isOk());
        mvc.perform(post("/api/productos").header("Authorization", t).contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isForbidden());
    }

    @Test void clienteNoListaUsuariosPeroGerenteSi() throws Exception {
        mvc.perform(get("/api/usuarios").header("Authorization", bearer("cliente@petsalud.cl"))).andExpect(status().isForbidden());
        mvc.perform(get("/api/usuarios").header("Authorization", bearer("empleado@petsalud.cl"))).andExpect(status().isForbidden());
        mvc.perform(get("/api/usuarios").header("Authorization", bearer("gerente@petsalud.cl"))).andExpect(status().isOk());
    }

    @Test void empleadoCreaProductoPeroNoLoElimina() throws Exception {
        String t = bearer("empleado@petsalud.cl");
        mvc.perform(post("/api/productos").header("Authorization", t).contentType(MediaType.APPLICATION_JSON)
                .content("{\"nombre\":\"Alimento\",\"categoria\":\"Alimentos\"}")).andExpect(status().isOk());
        mvc.perform(delete("/api/productos/1").header("Authorization", t)).andExpect(status().isForbidden());
        mvc.perform(delete("/api/productos/1").header("Authorization", bearer("gerente@petsalud.cl"))).andExpect(status().isNoContent());
    }

    @Test void clienteSoloVeSuPropioUsuario() throws Exception {
        Long idCliente = repo.findByEmail("cliente@petsalud.cl").get().getId();
        Long idGerente = repo.findByEmail("gerente@petsalud.cl").get().getId();
        String t = bearer("cliente@petsalud.cl");
        mvc.perform(get("/api/usuarios/" + idCliente).header("Authorization", t)).andExpect(status().isOk())
                .andExpect(jsonPath("$.password").doesNotExist());
        mvc.perform(get("/api/usuarios/" + idGerente).header("Authorization", t)).andExpect(status().isForbidden());
    }

    @Test void registroPublicoSiempreCreaClienteConPasswordHasheada() throws Exception {
        mvc.perform(post("/api/usuarios/registro").contentType(MediaType.APPLICATION_JSON)
                .content("{\"email\":\"nuevo@x.cl\",\"password\":\"Clave1234\",\"rol\":\"GERENTE\"}"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.rol").value("CLIENTE"));
        Usuario u = repo.findByEmail("nuevo@x.cl").get();
        assertTrue(u.getPassword().startsWith("$2"), "debe almacenarse con BCrypt");
    }

    @Test void bloqueoTrasIntentosFallidos() throws Exception {
        for (int i = 0; i < 3; i++) login("empleado@petsalud.cl", "incorrecta");
        mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
                .content("{\"email\":\"empleado@petsalud.cl\",\"password\":\"Clave1234\"}")).andExpect(status().isTooManyRequests());
    }
}
