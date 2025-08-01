package com.learning.springsecuritylab.dto;

import lombok.Getter;
import lombok.Setter;
import org.springframework.stereotype.Service;

@Setter
@Getter
public class RefreshTokenResponseDto {
    private String accessToken;
    private String refreshToken;
    private boolean isRefreshTokenNull;
    private boolean isRefreshTokenExpired;
}
