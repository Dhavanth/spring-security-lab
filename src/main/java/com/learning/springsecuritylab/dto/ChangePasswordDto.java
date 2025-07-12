package com.learning.springsecuritylab.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class ChangePasswordDto {
    private String userName;
    private  String password;
}
