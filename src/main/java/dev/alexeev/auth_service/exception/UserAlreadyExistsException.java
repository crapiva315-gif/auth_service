package dev.alexeev.auth_service.exception;

public class UserAlreadyExistsException extends RuntimeException {
  public UserAlreadyExistsException(String login) {
    super("User with login=" + login + " already exists");
  }
}