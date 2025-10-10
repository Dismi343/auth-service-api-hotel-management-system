package com.cpd.hotel_system.auth_service_api.service.impl;

import com.amazonaws.services.panorama.model.PackageImportJobStatus;
import com.cpd.hotel_system.auth_service_api.config.KeycloakSecurityUtil;
import com.cpd.hotel_system.auth_service_api.dto.request.PasswordRequestDto;
import com.cpd.hotel_system.auth_service_api.dto.request.RequestLoginDto;
import com.cpd.hotel_system.auth_service_api.dto.request.SystemUserRequestDto;
import com.cpd.hotel_system.auth_service_api.entity.Otp;
import com.cpd.hotel_system.auth_service_api.entity.SystemUser;
import com.cpd.hotel_system.auth_service_api.exceptions.BadRequestException;
import com.cpd.hotel_system.auth_service_api.exceptions.DuplicateEntryException;
import com.cpd.hotel_system.auth_service_api.exceptions.EntryNotFoundException;
import com.cpd.hotel_system.auth_service_api.exceptions.UnAuthorizedException;
import com.cpd.hotel_system.auth_service_api.repo.OtpRepo;
import com.cpd.hotel_system.auth_service_api.repo.SystemUserRepo;
import com.cpd.hotel_system.auth_service_api.service.EmailService;
import com.cpd.hotel_system.auth_service_api.service.SystemUserService;
import com.cpd.hotel_system.auth_service_api.util.OtpGenerator;

import jakarta.ws.rs.core.Response;
import lombok.RequiredArgsConstructor;
import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.time.Instant;
import java.util.*;

@Service
@RequiredArgsConstructor
 public class SystemUserServiceImpl implements SystemUserService {

    @Value("${keycloak.config.realm}")
    private String realm;

    private final SystemUserRepo systemUserRepo;
    private final KeycloakSecurityUtil keycloakSecurityUtil;
    private final OtpRepo otpRepo;
    private final OtpGenerator otpGenerator;
    private final EmailService emailService;

    @Override
    public void createUser(SystemUserRequestDto dto) throws IOException {
        if(dto.getFirstName() == null||dto.getFirstName().trim().isEmpty()){
                throw new BadRequestException("First name is required");
        }
        if(dto.getLastName() == null||dto.getLastName().trim().isEmpty()){
            throw new BadRequestException("Last name is required");
        }
        if(dto.getEmail() == null||dto.getEmail().trim().isEmpty()){
            throw new BadRequestException("Email name is required");
        }

        String userId ="";
        String otp ="";
        Keycloak keycloak=null;

        UserRepresentation existingUser=null;
        keycloak = keycloakSecurityUtil.getKeycloakInstance();

        existingUser=keycloak.realm(realm).users().search(dto.getEmail()).stream()
                .findFirst().orElse(null);

        if(existingUser!=null){
            Optional<SystemUser> selectedUserFromAuthService = systemUserRepo.findByEmail(dto.getEmail());
            if(selectedUserFromAuthService.isEmpty()){
                keycloak.realm(realm).users().delete(existingUser.getEmail());
            }else{
                throw new DuplicateEntryException("User with email "+dto.getEmail()+" already exists");
            }
        }else{
            Optional<SystemUser> selectedUserFromAuthService = systemUserRepo.findByEmail(dto.getEmail());

            if(selectedUserFromAuthService.isPresent()){
                Optional<Otp> selectedOtp =
                        otpRepo.findBySystemUserId(selectedUserFromAuthService.get().getUserId());
                if(selectedOtp.isPresent()){
                    otpRepo.deleteById(selectedOtp.get().getPropertyId());
                }
                systemUserRepo.deleteById(selectedUserFromAuthService.get().getUserId());
            }
        }

        UserRepresentation userRepresentation =mapUserRepo(dto,false,false);
        Response response = keycloak.realm(realm).users().create(userRepresentation);
        if(response.getStatus()== Response.Status.CREATED.getStatusCode()){
            RoleRepresentation userRole = keycloak.realm(realm).roles().get("user").toRepresentation();
            userId= response.getLocation().getPath().replaceAll(".*/([^/]+)$", "$1");
            keycloak.realm(realm).users().get(userId).roles().realmLevel().add(Arrays.asList(userRole));
           UserRepresentation createdUser= keycloak.realm(realm).users().get(userId).toRepresentation();

          SystemUser sUser= SystemUser.builder()
                   .userId(userId)
                   .keycloakId(createdUser.getId())
                   .firstName(dto.getFirstName())
                   .lastName(dto.getLastName())
                   .email(dto.getEmail())
                   .contact(dto.getContact())
                   .isActive(false)
                   .isAccountNonExpired(true)
                   .isAccountNonLocked(true)
                   .isCredentialsNonExpired(true)
                   .isEnabled(false)
                   .isEmailVerified(false)
                   .createdAt(new Date().toInstant())
                   .updatedAt(new Date().toInstant())
                   .build();

            SystemUser savedUser = systemUserRepo.save(sUser);

           Otp createdotp= Otp.builder()
                    .propertyId(UUID.randomUUID().toString())
                    .code(otpGenerator.generateOtp(5))
                    .createdAt(Instant.now())
                    .updatedAt(Instant.now())
                    .isVerified(false)
                    .attempts(0)
                    .build();

           otpRepo.save(createdotp);

           //Send Email

            emailService.sendUserSignupVerificationCode(dto.getEmail(),"Verify your email",createdotp.getCode(),dto.getFirstName());

        }
    }

    //===============================================================================================
    //===============================================================================================

    @Override
    public void initializeHosts(List<SystemUserRequestDto> users) throws IOException {
            for(SystemUserRequestDto dto:users){
                Optional<SystemUser> selectedUser= systemUserRepo.findByEmail(dto.getEmail());

                if(selectedUser.isPresent()){
                    continue;
                }

                String userId ="";
                String otp ="";
                Keycloak keycloak=null;

                UserRepresentation existingUser=null;
                keycloak = keycloakSecurityUtil.getKeycloakInstance();

                existingUser=keycloak.realm(realm).users().search(dto.getEmail()).stream()
                        .findFirst().orElse(null);

                if(existingUser!=null){
                    Optional<SystemUser> selectedUserFromAuthService = systemUserRepo.findByEmail(dto.getEmail());
                    if(selectedUserFromAuthService.isEmpty()){
                        keycloak.realm(realm).users().delete(existingUser.getEmail());
                    }else{
                        throw new DuplicateEntryException("User with email "+dto.getEmail()+" already exists");
                    }
                }else{
                    Optional<SystemUser> selectedUserFromAuthService = systemUserRepo.findByEmail(dto.getEmail());

                    if(selectedUserFromAuthService.isPresent()){
                        Optional<Otp> selectedOtp =
                                otpRepo.findBySystemUserId(selectedUserFromAuthService.get().getUserId());
                        if(selectedOtp.isPresent()){
                            otpRepo.deleteById(selectedOtp.get().getPropertyId());
                        }
                        systemUserRepo.deleteById(selectedUserFromAuthService.get().getUserId());
                    }
                }

                UserRepresentation userRepresentation =mapUserRepo(dto,true,true);
                Response response = keycloak.realm(realm).users().create(userRepresentation);
                if(response.getStatus()== Response.Status.CREATED.getStatusCode()){
                    RoleRepresentation userRole = keycloak.realm(realm).roles().get("host").toRepresentation();
                    userId= response.getLocation().getPath().replaceAll(".*/([^/]+)$", "$1");
                    keycloak.realm(realm).users().get(userId).roles().realmLevel().add(Arrays.asList(userRole));
                    UserRepresentation createdUser= keycloak.realm(realm).users().get(userId).toRepresentation();

                    SystemUser sUser= SystemUser.builder()
                            .userId(userId)
                            .keycloakId(createdUser.getId())
                            .firstName(dto.getFirstName())
                            .lastName(dto.getLastName())
                            .email(dto.getEmail())
                            .contact(dto.getContact())
                            .isActive(true)
                            .isAccountNonExpired(true)
                            .isAccountNonLocked(true)
                            .isCredentialsNonExpired(true)
                            .isEnabled(true)
                            .isEmailVerified(true)
                            .createdAt(new Date().toInstant())
                            .updatedAt(new Date().toInstant())
                            .build();

                    SystemUser savedUser = systemUserRepo.save(sUser);


                    //Send Email

                    emailService.sendHostPassword(dto.getEmail(),"access system by above password",dto.getPassword(),dto.getFirstName());

                }

            }
    }

    //===============================================================================================
    //===============================================================================================


    @Override
    public void reSend(String email,String type) {
        try{
            Optional<SystemUser> selectedUser=systemUserRepo.findByEmail(email);
            if(selectedUser.isEmpty()){
                throw new EntryNotFoundException("Unable to find any user associated with the provided email");
            }
            SystemUser systemUser = selectedUser.get();
            if(type.equalsIgnoreCase("SIGNUP")){

                if(systemUser.isEmailVerified()){
                    throw new DuplicateEntryException("This email is already verified");
                }
            }

            Otp selectedOtp= systemUser.getOtp();

                String code=otpGenerator.generateOtp(5);
                emailService.sendUserSignupVerificationCode(systemUser.getEmail(),"Verify your email",code,systemUser.getFirstName());

                selectedOtp.setAttempts(0);
                selectedOtp.setCode(code);
                selectedOtp.setVerified(false);
                selectedOtp.setUpdatedAt(new Date().toInstant());
                otpRepo.save(selectedOtp);



        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    //===============================================================================================
    //===============================================================================================

    @Override
    public void forgetPasswordSendVerificationCode(String email) {
        try {
            Optional<SystemUser> selectedUser = systemUserRepo.findByEmail(email);
            if (selectedUser.isEmpty()) {
                throw new EntryNotFoundException("Unable to find any user associated with the provided email");
            }
            SystemUser systemUser = selectedUser.get();

            Keycloak keycloak = null;
            keycloak = keycloakSecurityUtil.getKeycloakInstance();
            UserRepresentation existingUser = keycloak.realm(realm).users().search(email).stream().findFirst().orElse(null);

            if (existingUser != null) {
                throw new EntryNotFoundException("Unable to find any user associated with the provided email");
            }

            Otp selectedOtp = systemUser.getOtp();
            if (selectedOtp.getAttempts() >= 5) {
                String code = otpGenerator.generateOtp(5);
                emailService.sendUserSignupVerificationCode(systemUser.getEmail(), "Verify your email to reset Password", code, systemUser.getFirstName());

                selectedOtp.setAttempts(0);
                selectedOtp.setCode(code);
                selectedOtp.setVerified(false);
                selectedOtp.setUpdatedAt(new Date().toInstant());
                otpRepo.save(selectedOtp);


            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    //===============================================================================================
    //===============================================================================================


    @Override
    public boolean verifyReset(String otp, String email) {
        try{
            Optional<SystemUser> selectedUser = systemUserRepo.findByEmail(email);
            if (selectedUser.isEmpty()) {
                throw new EntryNotFoundException("Unable to find any user associated with the provided email");
            }

            SystemUser systemUserOb = selectedUser.get();
            Otp otpObj=systemUserOb.getOtp();

            if(otpObj.getCode().equals(otp)){
                //otpRepo.deleteById(otpObj.getPropertyId());
                otpObj.setAttempts(otpObj.getAttempts() + 1);
                otpObj.setUpdatedAt(new Date().toInstant());
                otpRepo.save(otpObj);
                otpObj.setVerified(true);
                return true;
            }else{
                if(otpObj.getAttempts()>=5){
                    reSend(email,"PASSWORD");
                    throw new BadRequestException("you have verification code");
                }
                otpObj.setAttempts(otpObj.getAttempts() + 1);
                otpObj.setUpdatedAt(new Date().toInstant());
                otpRepo.save(otpObj);
                return false;
            }

        }catch(Exception e){
            throw new RuntimeException(e);

        }
    }

    @Override
    public boolean passwordRest(PasswordRequestDto dto) {

            Optional<SystemUser> selectedUser = systemUserRepo.findByEmail(dto.getEmail());
            if (selectedUser.isPresent()) {
                SystemUser systemUser = selectedUser.get();
                Otp otpObj = systemUser.getOtp();
                Keycloak keycloak = keycloakSecurityUtil.getKeycloakInstance();
                List<UserRepresentation> keycloakUsers = keycloak.realm(realm).users().search(systemUser.getEmail());

                if (!keycloakUsers.isEmpty() && otpObj.getCode().equals(dto.getCode())) {
                    UserRepresentation keyclocakUser = keycloakUsers.get(0);
                    UserResource userResource = keycloak.realm(realm).users().get(keyclocakUser.getId());
                    CredentialRepresentation newPassword = new CredentialRepresentation();
                    newPassword.setType(CredentialRepresentation.PASSWORD);
                    newPassword.setValue(dto.getPassword());
                    newPassword.setTemporary(false);
                    userResource.resetPassword(newPassword);

                    systemUser.setUpdatedAt(new Date().toInstant());
                    systemUserRepo.save(systemUser);
                    return true;
                }
                throw new BadRequestException("try again");
            }
            throw new EntryNotFoundException("Unable to find ");
    }

    //===============================================================================================
    //===============================================================================================

    @Override
    public boolean verifyEmail(String otp, String email) {
        Optional<SystemUser> selectedUser = systemUserRepo.findByEmail(email);
        if (selectedUser.isEmpty()) {
            throw new EntryNotFoundException("can't find associated user");
        }
        SystemUser systemUser=selectedUser.get();
        Otp otpObj=systemUser.getOtp();

        if(otpObj.isVerified()){
            throw new BadRequestException("this otp has been used");
        }
        if(otpObj.getAttempts()>=5){
            reSend(email,"SIGNUP");
            return false;
        }
        if(otpObj.getCode().equals(otp)){
            UserRepresentation keycloakUser=keycloakSecurityUtil.getKeycloakInstance().realm(realm)
                    .users().search(email)
                    .stream().findFirst()
                    .orElseThrow(()->new EntryNotFoundException("user not found"));

            keycloakUser.setEmailVerified(true);
            keycloakUser.setEnabled(true);

            keycloakSecurityUtil.getKeycloakInstance().realm(realm)
                    .users().get(keycloakUser.getId())
                    .update(keycloakUser);

            systemUser.setEmailVerified(true);
            systemUser.setEnabled(true);
            systemUser.setActive(true);

            systemUserRepo.save(systemUser);

            otpObj.setVerified(true);
            otpObj.setAttempts(otpObj.getAttempts() + 1);
            otpRepo.save(otpObj);
            return true;
        }else{
            if(otpObj.getAttempts()>=5){
                reSend(email,"SIGNUP");
                return false;
            }
            otpObj.setAttempts(otpObj.getAttempts() + 1);
            otpRepo.save(otpObj);
        }
        return false;
    }


    //===============================================================================================
    //===============================================================================================



    @Override
    public Object userLogin(RequestLoginDto dto) {
        Optional<SystemUser> selectedUser = systemUserRepo.findByEmail(dto.getEmail());
        if (selectedUser.isEmpty()) {
            throw new EntryNotFoundException("can't find associated user");
        }
        SystemUser systemUser=selectedUser.get();
        if(!systemUser.isEmailVerified()){
            reSend(dto.getEmail(),"SIGNUP");
            throw new UnAuthorizedException("please verify your email");
        }
        MultiValueMap<String,String> requestBody =new LinkedMultiValueMap<>();
        requestBody.add("client_id","");
        requestBody.add("grant_type", OAuth2Constants.PASSWORD);
        requestBody.add("username",dto.getEmail());
        requestBody.add("client_secret","");
        requestBody.add("password",dto.getPassword());

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        RestTemplate restTemplate = new RestTemplate();
        ResponseEntity<Object> response=restTemplate.postForEntity("keycloak api url",requestBody,Object.class);

        return response.getBody();
    }


    //===============================================================================================
    //===============================================================================================


    private UserRepresentation mapUserRepo(SystemUserRequestDto dto,boolean isEmailVerified,boolean isEnabled){
        UserRepresentation user =new UserRepresentation();

        user.setEmail(dto.getEmail());
        user.setFirstName(dto.getFirstName());
        user.setLastName(dto.getLastName());
        user.setUsername(dto.getEmail());
        user.setEnabled(isEnabled);
        user.setEmailVerified(isEmailVerified);

        List<CredentialRepresentation> crerdList=new ArrayList<>();
        CredentialRepresentation cred=new CredentialRepresentation();
        cred.setTemporary(false);
        cred.setValue(dto.getPassword());
        crerdList.add(cred);
        user.setCredentials(crerdList);
        return user;
    }
}
