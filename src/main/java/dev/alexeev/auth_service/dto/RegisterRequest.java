package dev.alexeev.auth_service.dto;

import dev.alexeev.auth_service.entity.Credential;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;

@Getter @Setter
public class RegisterRequest {

  @NotBlank(message = "Login is required")
  private String login;

  @NotBlank(message = "Password is required")
  @Size(min = 8, message = "Password must be at least 8 characters long")
  private String password;

  @NotNull(message = "Role is required")
  private Credential.Role role;
}