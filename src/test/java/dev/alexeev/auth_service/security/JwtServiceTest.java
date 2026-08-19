package dev.alexeev.auth_service.security;

import io.jsonwebtoken.ExpiredJwtException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class JwtServiceTest {

  private static final String TEST_SECRET = "test-secret-key-must-be-at-least-32-bytes-long!";

  private JwtService jwtService;

  @BeforeEach
  void setUp() {
    jwtService = new JwtService(TEST_SECRET, 900000L, 604800000L);
  }

  @Test
  void constructor_shouldThrowException_whenSecretTooShort() {
    assertThatThrownBy(() -> new JwtService("too-short", 900000L, 604800000L))
            .isInstanceOf(IllegalStateException.class)
            .hasMessageContaining("at least 32 bytes");
  }

  @Test
  void generateAccessToken_shouldContainUserIdAndRole() {
    String token = jwtService.generateAccessToken(42L, "ADMIN");

    assertThat(jwtService.isTokenValid(token)).isTrue();
    assertThat(jwtService.extractUserId(token)).isEqualTo(42L);
    assertThat(jwtService.extractRole(token)).isEqualTo("ADMIN");
    assertThat(jwtService.isRefreshToken(token)).isFalse();
  }

  @Test
  void generateRefreshToken_shouldBeMarkedAsRefreshType() {
    String token = jwtService.generateRefreshToken(42L, "USER");

    assertThat(jwtService.isTokenValid(token)).isTrue();
    assertThat(jwtService.isRefreshToken(token)).isTrue();
  }

  @Test
  void isTokenValid_shouldReturnFalse_forMalformedToken() {
    assertThat(jwtService.isTokenValid("not-a-real-jwt-token")).isFalse();
  }

  @Test
  void isTokenValid_shouldReturnFalse_forTokenSignedWithDifferentSecret() {
    JwtService otherService = new JwtService(
            "different-secret-key-that-is-also-32-bytes-min", 900000L, 604800000L);
    String tokenFromOtherService = otherService.generateAccessToken(1L, "USER");

    assertThat(jwtService.isTokenValid(tokenFromOtherService)).isFalse();
  }

  @Test
  void isTokenValid_shouldReturnFalse_forExpiredToken() {
    JwtService shortLivedService = new JwtService(TEST_SECRET, -1000L, 604800000L);
    String expiredToken = shortLivedService.generateAccessToken(1L, "USER");

    assertThat(jwtService.isTokenValid(expiredToken)).isFalse();
  }

  @Test
  void parseToken_shouldThrowExpiredJwtException_whenTokenExpired() {
    JwtService shortLivedService = new JwtService(TEST_SECRET, -1000L, 604800000L);
    String expiredToken = shortLivedService.generateAccessToken(1L, "USER");

    assertThatThrownBy(() -> jwtService.parseToken(expiredToken))
            .isInstanceOf(ExpiredJwtException.class);
  }

  @Test
  void isRefreshToken_shouldReturnFalse_forInvalidToken() {
    assertThat(jwtService.isRefreshToken("garbage-token")).isFalse();
  }
}