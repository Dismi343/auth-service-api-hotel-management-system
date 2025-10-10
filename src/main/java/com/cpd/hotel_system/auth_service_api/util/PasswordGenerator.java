package com.cpd.hotel_system.auth_service_api.util;

import org.springframework.stereotype.Component;

import java.util.Random;

@Component
public class PasswordGenerator {
    private static final String UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final String LOWERCASE = "abcdefghijklmnopqrstuvwxyz";
    private static final String DIGITS = "0123456789";
    private static final String SPECIAL_CHARACTERS = "!@#$%^&*";

    private static final String ALL_CHARS = UPPERCASE + LOWERCASE + DIGITS + SPECIAL_CHARACTERS;

    public String generatePassword(){
        StringBuilder password = new StringBuilder(6);
        Random random = new Random();
        password.append(UPPERCASE.charAt(random.nextInt(UPPERCASE.length())));
        password.append(LOWERCASE.charAt(random.nextInt(LOWERCASE.length())));
        password.append(DIGITS.charAt(random.nextInt(DIGITS.length())));
        password.append(SPECIAL_CHARACTERS.charAt(random.nextInt(SPECIAL_CHARACTERS.length())));


        for(int i=4;i<6;i++){
            password.append(ALL_CHARS.charAt(random.nextInt(SPECIAL_CHARACTERS.length())));
        }
        return  shuffleString(password.toString(), random);
    }
    private String shuffleString(String input,Random random){
        char[] chars= input.toCharArray();

        for(int i=chars.length-1;i>0;i--){
            int j=random.nextInt(i+1);
            char temp=chars[i];
            chars[i]=chars[j];
            chars[j]=temp;
        }
        return new String(chars);
    }
}
