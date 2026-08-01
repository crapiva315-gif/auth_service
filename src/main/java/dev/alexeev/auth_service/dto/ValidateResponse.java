package dev.alexeev.auth_service.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class ValidateResponse {
  private boolean valid;
  private Long userId;
  private String role;
}