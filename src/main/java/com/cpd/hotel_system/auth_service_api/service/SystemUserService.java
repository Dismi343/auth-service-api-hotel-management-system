package com.cpd.hotel_system.auth_service_api.service;

import com.cpd.hotel_system.auth_service_api.dto.request.SystemUserRequestDto;

import java.io.IOException;
import java.util.ArrayList;

public interface SystemUserService {
    public void createUser(SystemUserRequestDto dto) throws IOException;
    public void initializeHosts(ArrayList<SystemUserRequestDto> users) throws IOException;
}
