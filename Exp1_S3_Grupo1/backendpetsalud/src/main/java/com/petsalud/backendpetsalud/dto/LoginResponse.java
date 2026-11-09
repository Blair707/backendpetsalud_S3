package com.petsalud.backendpetsalud.dto;

public record LoginResponse(String token, String tipo, String rol, long expiraEnMs) {}
