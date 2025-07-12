package com.learning.springsecuritylab.dto;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@RequiredArgsConstructor
public class SignUpRequestDto {
    private String userName;
    private String emailId;
    private String password;
    private String role;
}
