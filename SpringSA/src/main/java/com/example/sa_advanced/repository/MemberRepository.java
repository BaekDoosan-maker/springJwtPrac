package com.example.sa_advanced.repository;

import com.example.sa_advanced.domain.Member;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

/**
 * MemberRepository
 */
public interface MemberRepository extends JpaRepository<Member,Long> {

    Optional<Member> findByNickname(String username);

    Optional<Member> findById(Long id);

}
