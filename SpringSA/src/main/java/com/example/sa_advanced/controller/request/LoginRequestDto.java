package com.example.sa_advanced.controller.request;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;

import javax.validation.constraints.NotBlank;

/**
 * LoginRequestDto
 */
@Getter
@NoArgsConstructor
@RequiredArgsConstructor
public class LoginRequestDto {

    @NotBlank
    private String nickname; // nickname

    @NotBlank
    private String password; // password


}
