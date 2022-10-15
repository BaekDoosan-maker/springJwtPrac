package com.example.sa_advanced.repository;

import com.example.sa_advanced.domain.Member;
import com.example.sa_advanced.domain.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
  Optional<RefreshToken> findByMember(Member member);
}
