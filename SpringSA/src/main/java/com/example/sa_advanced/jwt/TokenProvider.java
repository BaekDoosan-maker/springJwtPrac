package com.example.sa_advanced.jwt;


import com.example.sa_advanced.controller.request.TokenDto;
import com.example.sa_advanced.controller.response.ResponseDto;
import com.example.sa_advanced.domain.Member;
import com.example.sa_advanced.domain.RefreshToken;
import com.example.sa_advanced.domain.UserDetailsImpl;
import com.example.sa_advanced.repository.RefreshTokenRepository;
import com.example.sa_advanced.shared.Authority;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.security.Key;
import java.util.Date;
import java.util.Optional;

@Slf4j // slf5j 를 사용하여 설정에 따라 다른 로깅 라이브러리를 사용할 수 있게 된다.
@Component
public class TokenProvider {

  private static final String AUTHORITIES_KEY = "auth";
  private static final String BEARER_PREFIX = "Bearer ";
  private static final long ACCESS_TOKEN_EXPIRE_TIME = 1000 * 60 * 30;            //30분
  private static final long REFRESH_TOKEN_EXPRIRE_TIME = 1000 * 60 * 60 * 24 * 7;     //7일

  private final Key key;
  private final RefreshTokenRepository refreshTokenRepository;

  /**
   * TokenProvider
   * @param secretKey
   * @param refreshTokenRepository
   */
  public TokenProvider(@Value("${jwt.secret}") String secretKey,
      RefreshTokenRepository refreshTokenRepository) {
    this.refreshTokenRepository = refreshTokenRepository;
    byte[] keyBytes = Decoders.BASE64.decode(secretKey); // BASE64 시크릿키 디코드
    this.key = Keys.hmacShaKeyFor(keyBytes);
  }

  /**
   * 토큰 생성 dto
   * @param member
   * @return
   */
  public TokenDto generateTokenDto(Member member) {
    long now = (new Date().getTime());  // 현재 시간 셋팅

    Date accessTokenExpiresIn = new Date(now + ACCESS_TOKEN_EXPIRE_TIME); // 엑세스 토큰 만료시간 셋팅( 현재시간 + 만료시간)
    String accessToken = Jwts.builder()
        .setSubject(member.getNickname())  // member에서 가저온 nickname값 넣고
        .claim(AUTHORITIES_KEY, Authority.ROLE_MEMBER.toString()) // 권한 넣고
        .setExpiration(accessTokenExpiresIn) // 엑세스 토큰 만료 시간 셋팅 값 넣고
        .signWith(key, SignatureAlgorithm.HS256) // 전자서명(SignatureAlgorithm) 넣고
        .compact();

    String refreshToken = Jwts.builder()
        .setExpiration(new Date(now + REFRESH_TOKEN_EXPRIRE_TIME))  // 리프레시 토큰 만료시간 셋팅
        .signWith(key, SignatureAlgorithm.HS256)  // 시그니처 알고리즘
        .compact();

    RefreshToken refreshTokenObject = RefreshToken.builder()
        .id(member.getId())
        .member(member)
        .value(refreshToken)
        .build();

    refreshTokenRepository.save(refreshTokenObject);

    return TokenDto.builder()
        .grantType(BEARER_PREFIX)
        .accessToken(accessToken)
        .accessTokenExpiresIn(accessTokenExpiresIn.getTime())
        .refreshToken(refreshToken)
        .build();
  }


  public Member getMemberFromAuthentication() {
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    if (authentication == null || AnonymousAuthenticationToken.class.
        isAssignableFrom(authentication.getClass())) {
      return null;
    }
    return ((UserDetailsImpl) authentication.getPrincipal()).getMember();
  }

  /**
   * jwt토큰 유효성 검사
   * @param token
   * @return
   */
  public boolean validateToken(String token) {
    try {
      Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
      return true;
    } catch (SecurityException | MalformedJwtException e) {
      log.info("Invalid JWT signature, 유효하지 않는 JWT 서명 입니다.");
    } catch (ExpiredJwtException e) {
      log.info("Expired JWT token, 만료된 JWT token 입니다.");
    } catch (UnsupportedJwtException e) {
      log.info("Unsupported JWT token, 지원되지 않는 JWT 토큰 입니다.");
    } catch (IllegalArgumentException e) {
      log.info("JWT claims is empty, 잘못된 JWT 토큰 입니다.");
    }
    return false;
  }


  @Transactional(readOnly = true)
  public RefreshToken isPresentRefreshToken(Member member) {
    Optional<RefreshToken> optionalRefreshToken = refreshTokenRepository.findByMember(member);
    return optionalRefreshToken.orElse(null);
  }

  /**
   * DeleteRefreshToken
   * @param member
   * @return
   */
  @Transactional
  public ResponseDto<?> deleteRefreshToken(Member member) {
    RefreshToken refreshToken = isPresentRefreshToken(member);
    if (null == refreshToken) { // refreshToken이 null일경우, "TOKEN_NOT_FOUND", "존재하지 않는 Token입니다" ResponseDto로 리턴
      return ResponseDto.fail("TOKEN_NOT_FOUND", "존재하지 않는 Token 입니다.");
    }

    refreshTokenRepository.delete(refreshToken);
    return ResponseDto.success("success"); // refreshTokenRepository에서 delete메소드로 refreshToken을 삭제하면 ,
                                                 // "success" ResponseDto로 리턴
  }
}
