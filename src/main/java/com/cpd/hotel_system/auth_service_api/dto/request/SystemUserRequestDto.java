package com.cpd.hotel_system.auth_service_api.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class SystemUserRequestDto {
    @NotBlank(message = "Fist name is required")
    @Size(max=100,message = "First Name must not exceed 100 characters")
    private String firstName;
    @NotBlank(message = "Last name is required")
    @Size(max=100,message = "Last Name must not exceed 100 characters")
    private String lastName;

    @NotBlank(message = "email is required")
    @Email(message = "email must be a valid email address")
    private String email;

    @NotBlank(message = "password is required")
    @Size(min=6,message = "password must be at least 6 characters")
    private String password;

    private String contact;
}
