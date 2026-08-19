package dev.alexeev.auth_service.service;

import dev.alexeev.auth_service.dto.LoginRequest;
import dev.alexeev.auth_service.dto.RefreshRequest;
import dev.alexeev.auth_service.dto.RegisterRequest;
import dev.alexeev.auth_service.dto.TokenResponse;
import dev.alexeev.auth_service.dto.ValidateResponse;
import dev.alexeev.auth_service.entity.Credential;
import dev.alexeev.auth_service.exception.InvalidCredentialsException;
import dev.alexeev.auth_service.exception.InvalidTokenException;
import dev.alexeev.auth_service.exception.UserAlreadyExistsException;
import dev.alexeev.auth_service.repository.CredentialRepository;
import dev.alexeev.auth_service.security.JwtService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

  @Mock
  private CredentialRepository credentialRepository;

  @Mock
  private JwtService jwtService;

  @Mock
  private BCryptPasswordEncoder passwordEncoder;

  @InjectMocks
  private AuthService authService;

  @AfterEach
  void clearSecurityContext() {
    SecurityContextHolder.clearContext();
  }

  // ---------- register ----------

  @Test
  void register_shouldForceUserRole_whenCallerIsAnonymous() {
    RegisterRequest request = new RegisterRequest();
    request.setUserId(1L);
    request.setLogin("newuser");
    request.setPassword("password123");
    request.setRole(Credential.Role.ADMIN); // попытка стать admin

    when(credentialRepository.existsByLogin("newuser")).thenReturn(false);
    when(passwordEncoder.encode("password123")).thenReturn("hashed");

    authService.register(request);

    ArgumentCaptor<Credential> captor = ArgumentCaptor.forClass(Credential.class);
    verify(credentialRepository).save(captor.capture());
    assertThat(captor.getValue().getRole()).isEqualTo(Credential.Role.USER);
  }

  @Test
  void register_shouldRespectRequestedRole_whenCallerIsAdmin() {
    setAuthenticatedAdmin();

    RegisterRequest request = new RegisterRequest();
    request.setUserId(2L);
    request.setLogin("newadmin");
    request.setPassword("password123");
    request.setRole(Credential.Role.ADMIN);

    when(credentialRepository.existsByLogin("newadmin")).thenReturn(false);
    when(passwordEncoder.encode("password123")).thenReturn("hashed");

    authService.register(request);

    ArgumentCaptor<Credential> captor = ArgumentCaptor.forClass(Credential.class);
    verify(credentialRepository).save(captor.capture());
    assertThat(captor.getValue().getRole()).isEqualTo(Credential.Role.ADMIN);
  }

  @Test
  void register_shouldThrowException_whenLoginAlreadyExists() {
    RegisterRequest request = new RegisterRequest();
    request.setUserId(1L);
    request.setLogin("existing");
    request.setPassword("password123");
    request.setRole(Credential.Role.USER);

    when(credentialRepository.existsByLogin("existing")).thenReturn(true);

    assertThatThrownBy(() -> authService.register(request))
            .isInstanceOf(UserAlreadyExistsException.class);

    verify(credentialRepository, never()).save(any());
  }

  // ---------- login ----------

  @Test
  void login_shouldReturnTokens_whenCredentialsAreValid() {
    Credential credential = new Credential();
    credential.setUserId(1L);
    credential.setLogin("testuser");
    credential.setPasswordHash("hashed");
    credential.setRole(Credential.Role.USER);

    LoginRequest request = new LoginRequest();
    request.setLogin("testuser");
    request.setPassword("password123");

    when(credentialRepository.findByLogin("testuser")).thenReturn(Optional.of(credential));
    when(passwordEncoder.matches("password123", "hashed")).thenReturn(true);
    when(jwtService.generateAccessToken(1L, "USER")).thenReturn("access-token");
    when(jwtService.generateRefreshToken(1L, "USER")).thenReturn("refresh-token");

    TokenResponse result = authService.login(request);

    assertThat(result.getAccessToken()).isEqualTo("access-token");
    assertThat(result.getRefreshToken()).isEqualTo("refresh-token");
  }

  @Test
  void login_shouldThrowException_whenLoginNotFound() {
    LoginRequest request = new LoginRequest();
    request.setLogin("unknown");
    request.setPassword("password123");

    when(credentialRepository.findByLogin("unknown")).thenReturn(Optional.empty());

    assertThatThrownBy(() -> authService.login(request))
            .isInstanceOf(InvalidCredentialsException.class);
  }

  @Test
  void login_shouldThrowException_whenPasswordDoesNotMatch() {
    Credential credential = new Credential();
    credential.setUserId(1L);
    credential.setLogin("testuser");
    credential.setPasswordHash("hashed");
    credential.setRole(Credential.Role.USER);

    LoginRequest request = new LoginRequest();
    request.setLogin("testuser");
    request.setPassword("wrongpassword");

    when(credentialRepository.findByLogin("testuser")).thenReturn(Optional.of(credential));
    when(passwordEncoder.matches("wrongpassword", "hashed")).thenReturn(false);

    assertThatThrownBy(() -> authService.login(request))
            .isInstanceOf(InvalidCredentialsException.class);
  }

  // ---------- validate ----------

  @Test
  void validate_shouldReturnValidTrue_whenTokenIsValid() {
    when(jwtService.isTokenValid("valid-token")).thenReturn(true);
    when(jwtService.extractUserId("valid-token")).thenReturn(1L);
    when(jwtService.extractRole("valid-token")).thenReturn("USER");

    ValidateResponse result = authService.validate("valid-token");

    assertThat(result.isValid()).isTrue();
    assertThat(result.getUserId()).isEqualTo(1L);
    assertThat(result.getRole()).isEqualTo("USER");
  }

  @Test
  void validate_shouldReturnValidFalse_whenTokenIsInvalid() {
    when(jwtService.isTokenValid("bad-token")).thenReturn(false);

    ValidateResponse result = authService.validate("bad-token");

    assertThat(result.isValid()).isFalse();
    assertThat(result.getUserId()).isNull();
    assertThat(result.getRole()).isNull();
  }

  // ---------- refresh ----------

  @Test
  void refresh_shouldReturnNewTokens_whenRefreshTokenIsValid() {
    RefreshRequest request = new RefreshRequest();
    request.setRefreshToken("valid-refresh");

    when(jwtService.isTokenValid("valid-refresh")).thenReturn(true);
    when(jwtService.isRefreshToken("valid-refresh")).thenReturn(true);
    when(jwtService.extractUserId("valid-refresh")).thenReturn(1L);
    when(jwtService.extractRole("valid-refresh")).thenReturn("USER");
    when(jwtService.generateAccessToken(1L, "USER")).thenReturn("new-access");
    when(jwtService.generateRefreshToken(1L, "USER")).thenReturn("new-refresh");

    TokenResponse result = authService.refresh(request);

    assertThat(result.getAccessToken()).isEqualTo("new-access");
    assertThat(result.getRefreshToken()).isEqualTo("new-refresh");
  }

  @Test
  void refresh_shouldThrowException_whenTokenIsNotRefreshType() {
    RefreshRequest request = new RefreshRequest();
    request.setRefreshToken("access-token-used-as-refresh");

    when(jwtService.isTokenValid("access-token-used-as-refresh")).thenReturn(true);
    when(jwtService.isRefreshToken("access-token-used-as-refresh")).thenReturn(false);

    assertThatThrownBy(() -> authService.refresh(request))
            .isInstanceOf(InvalidTokenException.class);
  }

  @Test
  void refresh_shouldThrowException_whenTokenIsExpiredOrInvalid() {
    RefreshRequest request = new RefreshRequest();
    request.setRefreshToken("expired-token");

    when(jwtService.isTokenValid("expired-token")).thenReturn(false);

    assertThatThrownBy(() -> authService.refresh(request))
            .isInstanceOf(InvalidTokenException.class);
  }

  // ---------- deleteByUserId ----------

  @Test
  void deleteByUserId_shouldDeleteCredential_whenExists() {
    Credential credential = new Credential();
    credential.setUserId(5L);

    when(credentialRepository.findByUserId(5L)).thenReturn(Optional.of(credential));

    authService.deleteByUserId(5L);

    verify(credentialRepository).delete(credential);
  }

  @Test
  void deleteByUserId_shouldDoNothing_whenNotFound() {
    when(credentialRepository.findByUserId(999L)).thenReturn(Optional.empty());

    authService.deleteByUserId(999L);

    verify(credentialRepository, never()).delete(any());
  }

  private void setAuthenticatedAdmin() {
    var authentication = new UsernamePasswordAuthenticationToken(
            1L, null, List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
    SecurityContextHolder.getContext().setAuthentication(authentication);
  }
}