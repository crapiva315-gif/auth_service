package dev.alexeev.auth_service.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Component
public class JwtService {

  private final SecretKey secretKey;
  private final long accessTokenExpirationMs;
  private final long refreshTokenExpirationMs;

  public JwtService(
          @Value("${jwt.secret}") String secret,
          @Value("${jwt.access-token-expiration-ms:900000}") long accessTokenExpirationMs,
          @Value("${jwt.refresh-token-expiration-ms:604800000}") long refreshTokenExpirationMs
  ) {
    byte[] keyBytes = secret.getBytes(StandardCharsets.UTF_8);
    if (keyBytes.length < 32) {
      throw new IllegalStateException(
              "JWT_SECRET must be at least 32 bytes (256 bits) long for HMAC-SHA256. Current length: " + keyBytes.length);
    }
    this.secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    this.accessTokenExpirationMs = accessTokenExpirationMs;
    this.refreshTokenExpirationMs = refreshTokenExpirationMs;
  }

  public String generateAccessToken(Long userId, String role) {
    return generateToken(userId, role, "ACCESS", accessTokenExpirationMs);
  }

  public String generateRefreshToken(Long userId, String role) {
    return generateToken(userId, role, "REFRESH", refreshTokenExpirationMs);
  }

  private String generateToken(Long userId, String role, String tokenType, long expirationMs) {
    Date now = new Date();
    Date expiry = new Date(now.getTime() + expirationMs);

    return Jwts.builder()
            .subject(String.valueOf(userId))
            .claim("role", role)
            .claim("type", tokenType)
            .issuedAt(now)
            .expiration(expiry)
            .signWith(secretKey)
            .compact();
  }

  public Claims parseToken(String token) {
    return Jwts.parser()
            .verifyWith(secretKey)
            .build()
            .parseSignedClaims(token)
            .getPayload();
  }

  public boolean isTokenValid(String token) {
    try {
      parseToken(token);
      return true;
    } catch (JwtException | IllegalArgumentException e) {
      return false;
    }
  }

  public boolean isRefreshToken(String token) {
    try {
      return "REFRESH".equals(parseToken(token).get("type", String.class));
    } catch (JwtException e) {
      return false;
    }
  }

  public Long extractUserId(String token) {
    return Long.valueOf(parseToken(token).getSubject());
  }

  public String extractRole(String token) {
    return parseToken(token).get("role", String.class);
  }
}