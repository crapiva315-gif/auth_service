package dev.alexeev.auth_service.controller;

import dev.alexeev.auth_service.dto.*;
import dev.alexeev.auth_service.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

  private final AuthService authService;

  @PostMapping("/register")
  public ResponseEntity<RegisterResponse> register(@Valid @RequestBody RegisterRequest request) {
    RegisterResponse response = authService.register(request);
    return ResponseEntity.status(HttpStatus.CREATED).body(response);
  }

  @PostMapping("/login")
  public ResponseEntity<TokenResponse> login(@Valid @RequestBody LoginRequest request) {
    return ResponseEntity.ok(authService.login(request));
  }

  @PostMapping("/validate")
  public ResponseEntity<ValidateResponse> validate(@RequestParam String token) {
    return ResponseEntity.ok(authService.validate(token));
  }

  @PostMapping("/refresh")
  public ResponseEntity<TokenResponse> refresh(@Valid @RequestBody RefreshRequest request) {
    return ResponseEntity.ok(authService.refresh(request));
  }

  @PreAuthorize("hasRole('ADMIN')")
  @DeleteMapping("/credentials/{userId}")
  public ResponseEntity<Void> deleteByUserId(@PathVariable Long userId) {
    authService.deleteByUserId(userId);
    return ResponseEntity.noContent().build();
  }
}