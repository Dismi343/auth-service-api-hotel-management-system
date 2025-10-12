package com.cpd.hotel_system.auth_service_api.api;

import com.cpd.hotel_system.auth_service_api.config.JwtService;
import com.cpd.hotel_system.auth_service_api.dto.request.PasswordRequestDto;
import com.cpd.hotel_system.auth_service_api.dto.request.RequestLoginDto;
import com.cpd.hotel_system.auth_service_api.dto.request.SystemUserRequestDto;
import com.cpd.hotel_system.auth_service_api.service.SystemUserService;
import com.cpd.hotel_system.auth_service_api.util.StandardResponseDto;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;

@RestController
@RequestMapping("user-service/api/v1/users")
@RequiredArgsConstructor
public class UserController {

    private final SystemUserService systemUserService;
    private final JwtService jwtService;

    @PostMapping("/visitors/singup")
    public ResponseEntity<StandardResponseDto> createUser(
        @RequestBody SystemUserRequestDto dto
        ){
        try {
            systemUserService.createUser(dto);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return new ResponseEntity<>(
                new StandardResponseDto(
                        201,
                        "User created successfully",
                        null
                ),HttpStatus.CREATED
        );
    }

    @PostMapping("/visitors/resend")
    public ResponseEntity<StandardResponseDto> reSend(
            @RequestParam String email,
            @RequestParam String type
    ){
        systemUserService.reSend(email, type);
        return new ResponseEntity<>(
                new StandardResponseDto(
                        200,
                        "Please check your email",
                        null
                ),HttpStatus.OK
        );
    }

    @PostMapping("/visitors/forgot-password-request-code")
    public ResponseEntity<StandardResponseDto> forgotPasswordRequest(
            @RequestParam String email
    ){
        systemUserService.forgetPasswordSendVerificationCode(email);
        return new ResponseEntity<>(
                new StandardResponseDto(
                        200,
                        "Please check your email",
                        null
                ),HttpStatus.OK
        );
    }


    @PostMapping("/visitors/verify-reset")
    public ResponseEntity<StandardResponseDto> verifyReset(
            @RequestParam String email,
            @RequestParam String otp
    ){
        boolean isVerified=systemUserService.verifyReset(otp,email);



        return new ResponseEntity<>(
                new StandardResponseDto(
                        isVerified?200:400,
                        isVerified?"Verifies":"try again",
                        isVerified
                ),isVerified?HttpStatus.OK:HttpStatus.BAD_REQUEST
        );
    }


    @PostMapping("/visitors/reset-password")
    public ResponseEntity<StandardResponseDto> resetPassword(
            @RequestBody PasswordRequestDto dto
    ){
        boolean isChanged=systemUserService.passwordRest(dto);
        return new ResponseEntity<>(
                new StandardResponseDto(
                        isChanged?200:400,
                        isChanged?"changed":"try again",
                        isChanged
                ),isChanged?HttpStatus.OK:HttpStatus.BAD_REQUEST
        );
    }

    @PostMapping("/visitors/verify-email")
    public ResponseEntity<StandardResponseDto> verifyEmail(
            @RequestParam String email,
            @RequestParam String otp
    ){
        boolean isVerified=systemUserService.verifyEmail(otp,email);

        return new ResponseEntity<>(
                new StandardResponseDto(
                        isVerified?200:400,
                        isVerified?"Verifies":"try again",
                        isVerified
                ),isVerified?HttpStatus.OK:HttpStatus.BAD_REQUEST
        );
    }

    @PostMapping("/visitors/login")
    public ResponseEntity<StandardResponseDto> login(
            @RequestBody RequestLoginDto dto
            ){




        return new ResponseEntity<>(
                new StandardResponseDto(
                        200,
                        "Login successful",
                        systemUserService.userLogin(dto)
                ),HttpStatus.OK
        );
    }

}
