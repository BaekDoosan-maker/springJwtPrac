package com.example.sa_advanced.service;
import com.example.sa_advanced.controller.request.LoginRequestDto;
import com.example.sa_advanced.controller.request.MemberRequestDto;
import com.example.sa_advanced.controller.request.TokenDto;
import com.example.sa_advanced.controller.response.MemberResponseDto;
import com.example.sa_advanced.controller.response.ResponseDto;
import com.example.sa_advanced.domain.Member;
import com.example.sa_advanced.jwt.TokenProvider;
import com.example.sa_advanced.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.util.Optional;

/**
 * MemberService
 */
@RequiredArgsConstructor
@Service
public class MemberService {
    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;
    private final TokenProvider tokenProvider;

    /**
     * 회원가입 - 유저등록
     * @param requestDto
     * @return
     * @author doosan
     */
    @Transactional /*  1. 닉네임 중복 체크  */
    public ResponseDto<?> createMember(MemberRequestDto requestDto) {
        if (null != isPresentMember(requestDto.getNickname())) {
            return ResponseDto.fail("DUPLICATED_NICKNAME",
                    "중복된 닉네임 입니다.");
        }

        /* 2. 비밀번호 유효성 체크 */
        if (!requestDto.getPassword().equals(requestDto.getPasswordConfirm())) {
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

    /**
     * 로그인
     * @param requestDto
     * @param response
     * @return
     * @author doosan
     */
    @Transactional /* 로그인 - 유저 아이디 유효성 체크*/
    public ResponseDto<?> login(LoginRequestDto requestDto, HttpServletResponse response) {
        Member member = isPresentMember(requestDto.getNickname());
        if (null == member) {  // member가 null이면 "MEMBER_NOT_FOUND" , "사용자를 찾을 수 없습니다"  예외처리
            return ResponseDto.fail("MEMBER_NOT_FOUND",
                    "사용자를 찾을 수 없습니다.");
        }
        /*  비밀번호 유효성 검증  - Jwt token 을 encoding한 내용에 들어있는 비밀번호와  Dto에서 가저온 비밀번호가 같지 않으면 "INVALIED_MEMEBER" , "사용자를 찾을 수 없습니다." 예외처리 */
        if (!member.validatePassword(passwordEncoder, requestDto.getPassword())) {
            return ResponseDto.fail("INVALID_MEMBER", "사용자를 찾을 수 없습니다.");
        }

            TokenDto tokenDto = tokenProvider.generateTokenDto(member);
            tokenToHeaders(tokenDto, response);

            return ResponseDto.success( //ResponseDto 로 success 리턴 할때, MemberResponseDto.builder() 에 id, nickname, createdAt, modifiedAt, email을 담아서 리턴
                    MemberResponseDto.builder()
                            .id(member.getId()) // member 에서 id를 가저오고
                            .nickname(member.getNickname()) // member에서 nickname 가저오고
                            .createdAt(member.getCreatedAt()) // member에서 createdAt 가저오고
                            .modifiedAt(member.getModifiedAt()) // member에서 modifiedAt 가저오고
                            .email(member.getEmail()) // member에서 email 가저오고
                            .build()
            );
        }

    /**
     * Logout
     * @param request
     * @return
     * @author doosan
     */
    public ResponseDto<?> logout (HttpServletRequest request){
            if (!tokenProvider.validateToken(request.getHeader("Refresh-Token"))) {  //tokenProvider에서 가저온 토큰값이 heaader에서 가저온 Refresh-Token이 아니라면,
                return ResponseDto.fail("INVALID_TOKEN", "Token이 유효하지 않습니다."); //"INVALID_TOKEN", "Token이 유효하지 않습니다" ResponseDto로 리턴
            }
            Member member = (Member) tokenProvider.getMemberFromAuthentication();
            if (null == member) { //member가 null이라면, "MEMBER_NOT_FOUND", "사용자를 찾을 수 없습니다" ResponseDto로 리턴
                return ResponseDto.fail("MEMBER_NOT_FOUND",
                        "사용자를 찾을 수 없습니다.");
            }
            return tokenProvider.deleteRefreshToken(member); // deleteRefreshToken
        }

         /* readOnly = true: 데이터의 변경이 없는 읽기 전용 메서드에 사용, 영속성 컨텍스트를 플러시 하지 않으므로 약간의 성능 향상*/
        @Transactional(readOnly = true) // @Transactional은 클래스, 인터페이스, 메소드에 사용할수 있다. 메서드에 가장 가까운 어노테이션이 우선순위를 가진다.
        public Member isPresentMember (String nickname) { // 보통 클래스에 @Transactional(readOnly = true)를 선언해 놓고, 엔티티의 등록, 수정, 삭제가 동작되는 메서드에 @Transactional을 선언하여 사용한다.
            Optional<Member> optionalMember = memberRepository.findByNickname(nickname);
            return optionalMember.orElse(null);
        }

        /* Jwt Token Header */
        public void tokenToHeaders (TokenDto tokenDto, HttpServletResponse response) {  // jwt Token header에
            response.addHeader("Authorization", "Bearer " + tokenDto.getAccessToken()); // "Authorization" , "Bearer + 토큰Dto에서가저온 AccessToken" 을 header에 add
            response.addHeader("Rrefresh-Token", tokenDto.getRefreshToken()); // "Refresh-Token", "tokenDto에서 가저온 RefreshToken을 hearder에 add
            response.addHeader("Access-Token-Expire-Time", tokenDto.getAccessTokenExpiresIn().toString()); // "Access-Token-Expire-Time" , "tokenDto에서 가저온 토큰만료시간을 string타입으로 add.
        }
    }