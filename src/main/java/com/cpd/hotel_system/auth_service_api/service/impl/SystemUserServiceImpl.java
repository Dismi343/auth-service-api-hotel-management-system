package com.cpd.hotel_system.auth_service_api.service.impl;

import com.cpd.hotel_system.auth_service_api.config.KeycloakSecurityUtil;
import com.cpd.hotel_system.auth_service_api.dto.request.SystemUserRequestDto;
import com.cpd.hotel_system.auth_service_api.entity.Otp;
import com.cpd.hotel_system.auth_service_api.entity.SystemUser;
import com.cpd.hotel_system.auth_service_api.exceptions.BadRequestException;
import com.cpd.hotel_system.auth_service_api.exceptions.DuplicateEntryException;
import com.cpd.hotel_system.auth_service_api.repo.OtpRepo;
import com.cpd.hotel_system.auth_service_api.repo.SystemUserRepo;
import com.cpd.hotel_system.auth_service_api.service.SystemUserService;
import lombok.RequiredArgsConstructor;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class SystemUserServiceImpl implements SystemUserService {

    @Value("${keycloak.config.realm}")
    private String realm;

    private final SystemUserRepo systemUserRepo;
    private final KeycloakSecurityUtil keycloakSecurityUtil;
    private final OtpRepo otpRepo;

    @Override
    public void createUser(SystemUserRequestDto dto) {
        if(dto.getFirstName() == null||dto.getFirstName().trim().isEmpty()){
                throw new BadRequestException("First name is required");
        }
        if(dto.getLastName() == null||dto.getLastName().trim().isEmpty()){
            throw new BadRequestException("Last name is required");
        }
        if(dto.getEmail() == null||dto.getEmail().trim().isEmpty()){
            throw new BadRequestException("Email name is required");
        }

        String userId;
        String otp;
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

        //

    }

    private UserRepresentation mapUserRepo(SystemUserRequestDto dto){
        UserRepresentation user =new UserRepresentation();

        user.setEmail(dto.getEmail());
        user.setFirstName(dto.getFirstName());
        user.setLastName(dto.getLastName());
        user.setUsername(dto.getEmail());
        user.setEnabled(false);
        user.setEmailVerified(false);

        List<CredentialRepresentation> crerdList=new ArrayList<>();
        CredentialRepresentation cred=new CredentialRepresentation();
        cred.setTemporary(false);
        cred.setValue(dto.getPassword());
        crerdList.add(cred);
        user.setCredentials(crerdList);
        return user;
    }
}
