package dev.alexeev.auth_service.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

@Getter @Setter
public class LoginRequest {
  @NotBlank(message = "Login is required")
  private String login;

  @NotBlank(message = "Password is required")
  private String password;
}