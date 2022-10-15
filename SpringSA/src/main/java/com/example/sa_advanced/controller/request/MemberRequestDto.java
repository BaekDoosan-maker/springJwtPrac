package com.example.sa_advanced.controller.request;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Pattern;
import javax.validation.constraints.Size;

/**
 * MemberRequestDto
 *
 */
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class MemberRequestDto {


    @NotBlank(message = "{member.nickname.notblank}")
    @Size(mIn=4,max=12, message= "{member.nickname.size}")
    private String nickname; // nickname

    @NotBlank(message = "{member.nickname.notblank}")
    @Size(mIn=8,max=20, message= "{member.nickname.size}")
    private String password; // password

    @NotBlank(message = "{member.nickname.notblank}")
    @Size(mIn=8,max=20, message= "{member.nickname.size}")
    private String username; // username

    @NotBlank
    public String getPasswordConfirm;

}
