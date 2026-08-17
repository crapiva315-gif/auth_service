package dev.alexeev.auth_service.repository;

import dev.alexeev.auth_service.entity.Credential;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface CredentialRepository extends JpaRepository<Credential, Long> {
  Optional<Credential> findByLogin(String login);
  Optional<Credential> findByUserId(Long userId);
  boolean existsByLogin(String login);
}