package com.example.sa_advanced.controller;

import com.example.sa_advanced.controller.request.LoginRequestDto;
import com.example.sa_advanced.controller.request.MemberRequestDto;
import com.example.sa_advanced.controller.response.ResponseDto;
import com.example.sa_advanced.service.MemberService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;

/**
 * MemberController
 */
@RequiredArgsConstructor
@RestController
public class MemberController {
    private final MemberService memberService;

    /**
     * signup 맵핑
     * @param requestDto
     * @return
     * @author doosan
     */
    @PostMapping(value = "/api/member/signup")
    public ResponseDto<?> signup(@RequestBody @Valid MemberRequestDto requestDto) {
        return memberService.createMember(requestDto);
    }

    /**
     * login 맵핑
     * @param requestDto
     * @param response
     * @return
     * @author doosan
     */
    @PostMapping(value = "api/member/login")
    public  ResponseDto<?> login (@RequestBody @Valid LoginRequestDto requestDto, HttpServletResponse response ) {
        return memberService.login(requestDto , response);
    }

    /**
     * logout 맵핑
     * @param request
     * @return
     * @author doosan
     */
    @PostMapping(value="/api/auth/member/logout")
    public ResponseDto<?> logout(HttpServletRequest request) {
        return memberService.logout(request);
    }
}
