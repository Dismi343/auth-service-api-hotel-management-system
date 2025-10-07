package com.cpd.hotel_system.auth_service_api.util;


import lombok.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class StandardResponseDto {
    private int status;
    private String message;
   private Object data;
}
