package com.cpd.hotel_system.auth_service_api.service;

import com.cpd.hotel_system.auth_service_api.dto.request.SystemUserRequestDto;

import java.io.IOException;

public interface SystemUserService {
    public void createUser(SystemUserRequestDto dto) throws IOException;

}
