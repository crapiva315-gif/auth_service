package dev.alexeev.auth_service.exception;

public class InvalidCredentialsException extends RuntimeException {
  public InvalidCredentialsException() {
    super("Invalid login or password");
  }
}