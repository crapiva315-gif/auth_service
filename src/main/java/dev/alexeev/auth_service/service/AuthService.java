package dev.alexeev.auth_service.service;

import dev.alexeev.auth_service.dto.*;
import dev.alexeev.auth_service.entity.Credential;
import dev.alexeev.auth_service.exception.InvalidCredentialsException;
import dev.alexeev.auth_service.exception.InvalidTokenException;
import dev.alexeev.auth_service.exception.UserAlreadyExistsException;
import dev.alexeev.auth_service.repository.CredentialRepository;
import dev.alexeev.auth_service.security.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Objects;

@Service
@RequiredArgsConstructor
public class AuthService {

  private final CredentialRepository credentialRepository;
  private final JwtService jwtService;
  private final BCryptPasswordEncoder passwordEncoder;

  @Transactional
  public void register(RegisterRequest request) {
    if (credentialRepository.existsByLogin(request.getLogin())) {
      throw new UserAlreadyExistsException(request.getLogin());
    }

    Credential credential = new Credential();
    credential.setUserId(request.getUserId());
    credential.setLogin(request.getLogin());
    credential.setPasswordHash(passwordEncoder.encode(request.getPassword()));
    credential.setRole(resolveAllowedRole(request.getRole()));

    credentialRepository.save(credential);
  }

  private Credential.Role resolveAllowedRole(Credential.Role requestedRole) {
    var authentication = org.springframework.security.core.context.SecurityContextHolder
            .getContext().getAuthentication();

    boolean callerIsAdmin = authentication != null
            && authentication.isAuthenticated()
            && authentication.getAuthorities().stream()
            .anyMatch(a -> Objects.equals(a.getAuthority(), "ROLE_ADMIN"));

    if (callerIsAdmin) {
      return requestedRole;
    }
    return Credential.Role.USER;
  }

  @Transactional(readOnly = true)
  public TokenResponse login(LoginRequest request) {
    Credential credential = credentialRepository.findByLogin(request.getLogin())
            .orElseThrow(InvalidCredentialsException::new);

    if (!passwordEncoder.matches(request.getPassword(), credential.getPasswordHash())) {
      throw new InvalidCredentialsException();
    }

    String accessToken = jwtService.generateAccessToken(credential.getUserId(), credential.getRole().name());
    String refreshToken = jwtService.generateRefreshToken(credential.getUserId(), credential.getRole().name());

    return new TokenResponse(accessToken, refreshToken);
  }

  public ValidateResponse validate(String token) {
    if (!jwtService.isTokenValid(token)) {
      return new ValidateResponse(false, null, null);
    }
    return new ValidateResponse(true, jwtService.extractUserId(token), jwtService.extractRole(token));
  }

  public TokenResponse refresh(RefreshRequest request) {
    String token = request.getRefreshToken();

    if (!jwtService.isTokenValid(token) || !jwtService.isRefreshToken(token)) {
      throw new InvalidTokenException("Invalid or expired refresh token");
    }

    Long userId = jwtService.extractUserId(token);
    String role = jwtService.extractRole(token);

    return new TokenResponse(
            jwtService.generateAccessToken(userId, role),
            jwtService.generateRefreshToken(userId, role)
    );
  }

  @Transactional
  public void deleteByUserId(Long userId) {
    credentialRepository.findByUserId(userId)
            .ifPresent(credentialRepository::delete);
  }
}