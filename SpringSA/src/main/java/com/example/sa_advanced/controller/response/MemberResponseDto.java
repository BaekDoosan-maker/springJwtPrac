package com.example.sa_advanced.controller.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import java.time.LocalDateTime;

/**
 * MemberResponseDto
 */
@Builder
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class MemberResponseDto {
    private Long id; // 아이디
    private String nickname;  // 닉네임
    private LocalDateTime createdAt; // 생성일
    private java.time.LocalDateTime modifiedAt; // 수정일
    private String email; //이메일

}
