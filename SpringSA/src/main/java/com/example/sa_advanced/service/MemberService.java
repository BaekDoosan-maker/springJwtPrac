package com.example.sa_advanced.service;
import com.example.sa_advanced.controller.request.LoginRequestDto;
import com.example.sa_advanced.controller.request.MemberRequestDto;
import com.example.sa_advanced.controller.request.TokenDto;
import com.example.sa_advanced.controller.response.MemberResponseDto;
import com.example.sa_advanced.controller.response.ResponseDto;
import com.example.sa_advanced.jwt.TokenProvider;
import com.example.sa_advanced.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.lang.reflect.Member;
import java.util.Optional;
/**
 * MemberService
 */
@RequiredArgsConstructor
@Service
public class MemberService {
    private MemberRepository memberRepository;

    private final PasswordEncoder passwordEncoder;
    private final TokenProvider tokenProvider;

    @Transactional /*  1. 닉네임 중복 체크  */
    public ResponseDto<?> createMember(MemberRequestDto requestDto) {
        if (null != isPresentMember(requestDto.getNickname())) {
            return ResponseDto.fail("DUPLICATED_NICKNAME",
                    "중복된 닉네임 입니다.");
        }

        /* 2. 비밀번호 유효성 체크 */
        if (requestDto.getPassword().equals(requestDto.getPasswordConfirm())) {
            return ResponseDto.fail("PASSWORDS_NOT_MATCHED",
                    "비밀번호와 비밀번호 확인이 일치하지 않습니다.");
        }

        //빌더 패턴
        Member member = Member.builder()
                .nickname(requestDto.getNickname())
                  .password(passwordEncoder.encode(requestDto.getPassword()))
                    .build();
        memberRepository.save(member);
        return ResponseDto.success(
                MemberResponseDto.builder()
                        .id(member.getId())
                        .nickname(member.getNickname())
                        .createdAt(member.getCreatedAt())
                        .modifiedAt(member.getModifiedAt())
                        .build()
        );
    }

    @Transactional
    public ResponseDto<?> login(LoginRequestDto requestDto, HttpServletResponse response) {
        Member member = isPresentMember(requestDto.getNickname());
        if (null == member) {
            return ResponseDto.fail("MEMBER_NOT_FOUND",
                    "사용자를 찾을 수 없습니다.");
        }

        if (!member.validatePassword(passwordEncoder, requestDto.getPassword())) {
            return ResponseDto.fail("INVALID_MEMBER", "사용자를 찾을 수 없습니다.");
        }

            TokenDto tokenDto = tokenProvider.generateTokenDto((com.example.sa_advanced.domain.Member) member);
            tokenToHeaders(tokenDto, response);

            return ResponseDto.success(
                    MemberResponseDto.builder()
                            .id(((com.example.sa_advanced.domain.Member) member).getId())
                            .nickname(member.getNicknamer())
                            .createdAt(member.getCreatedAt())
                            .modifiedAt(member.getModifiers())
                            .build()
            );
        }

        public ResponseDto<?> logout (HttpServletRequest request){
            if (!tokenProvider.validateToken(request.getHeader("Refresh-Token"))) {
                return ResponseDto.fail("INVALID_TOKEN", "Token이 유효하지 않습니다.");
            }
            Member member = (Member) tokenProvider.getMemberFromAuthentication();
            if (null == member) {
                return ResponseDto.fail("MEMBER_NOT_FOUND",
                        "사용자를 찾을 수 없습니다.");
            }
            return tokenProvider.deleteRefreshToken((com.example.sa_advanced.domain.Member) member);
        }

        public Member isPresentMember (String nickname){
            Optional<com.example.sa_advanced.domain.Member> optionalMember = memberRepository.findByNickname(nickname);
            return (Member) optionalMember.orElse(null);
        }

        public void tokenToHeaders (TokenDto tokenDto, HttpServletResponse response){
            response.addHeader("Authorization", "Bearer " + tokenDto.getAccessToken());
            response.addHeader("Rrefresh-Token", tokenDto.getRefreshToken());
            response.addHeader("Access-Token-Expire-Time", tokenDto.getAccessTokenExpiresIn().toString());
        }

    }


