package com.example.sa_advanced.controller.request;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Pattern;
import javax.validation.constraints.Size;

/**
 * MemberRequestDto
 */
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class MemberRequestDto {
    /* @NotBlank :  null값 ,빈값, 공백 허용안함*/
    @NotBlank(message = "{member.nickname.notblank}") //
    @Size(min=4,max=12, message= "{member.nickname.size}") // nickname 글자수 4자~ 12자
    @Pattern(regexp = "[a-z\\d]*${3,12}", message = "{member.nickname.pattern}")  // 아닐경우 유효성 검사 메시지 출력
    private String nickname; // nickname

    @NotBlank(message = "{member.password.notblank}")
    @Size(min=8,max=20, message= "{member.password.size}")
    @Pattern(regexp = "^(?=.*[A-Za-z])(?=.*\\d)(?=.*[~!@#$%^&*()+|=])[A-Za-z\\d~!@#$%^&*()+|=]{8,16}$" , message = "{member.password.pattern}")
    private String password; // password

    @NotBlank(message = "{member.username.notblank}")
    @Size(min=8,max=20, message= "{member.username.size}")
    private String username; // username

    //@NotBlank(message = "member.email.notblank")
    @Size(min=2,max=20, message= "{member.email.size}")
    private String email; // email

    @NotBlank
    public String passwordConfirm;

}
