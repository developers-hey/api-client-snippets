package com.heybanco.baas.consumer;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.shaded.gson.JsonObject;
import com.nimbusds.jose.shaded.gson.JsonParser;

import java.io.*;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.text.ParseException;
import java.util.HashMap;
import java.util.Map;

import java.util.Properties;
import java.util.logging.*;

public class ClienteImpExample {
    private static final Logger logger = Logger.getLogger(ClienteImpExample.class.getName());
    private static final String HOSTNAME = "https://test-tech.hey.inc";
    private static final String CLIENT_ID = "bank-app";
    private static final String CLIENT_SECRET = "abf3714d-1a00-4b1e-9ad4-7d4554105c7c";
    private static final String B_APPLICATION = "abf3714d-1a00-4b1e-9ad4-7d4554105c7c";
    public static void main(String[] args) {
        Properties prop = new Properties();
        FileInputStream input = null;
        String method = "POST";
        String endpoind="/api/taas/v1.0/accounts";
       APIConsumer apiConsumer = new APIConsumer(prop);
        try {
            input = new FileInputStream("../APIConsumer/src/main/resources/config.properties");
            prop.load(input);
            JsonObject jsonResponse = JsonParser.parseString(apiConsumer.getAuthorizationToken(CLIENT_ID, CLIENT_SECRET)).getAsJsonObject();
            String accessToken = jsonResponse.get("access_token").getAsString();
            Map<String, String> headers = new HashMap<String, String>() {{
                put("Accept", "application/json");
                put("Content-Type", "application/json");
                put("B-Transaction", "123456789");
                put("Accept-Charset", "UTF-8");
                put("B-application", B_APPLICATION);
                put("Authorization", "Bearer " + accessToken);
            }};
            String requestPayload ="{\"taxRegimeId\": 2,\"name\": \"Jose Luis\",\"lastName\": \"Lemuus\",\"secondLastName\": \"Valdivia\",\"businessName\": \"\",\"birthday\": \"1996-10-03\",\"rfc\": \"LEVL961003KQ0\",\"curp\": \"LEVL961003HBSMLS06\",\"callingCode\": \"52\",\"cellPhoneNumber\": \"3311065681\",\"email\": \"jose.lemus@banregio.com\",\"nationalityId\": \"001\",\"countryId\": \"01\",\"stateId\": \"047\",\"cityId\": \"04701005\",\"legalRepresentative\": {\"name\": \"\",\"lastName\": \"\",\"secondLastName\": \"\"}}";
            String encryptedPayload = apiConsumer.signAndEncryptPayload(requestPayload,B_APPLICATION );
             requestPayload = "{\"data\":\"" + encryptedPayload + "\"}";
           String response = apiConsumer.sendRequest(method, HOSTNAME+endpoind, headers, requestPayload,null,null);
            logger.log(Level.INFO,response);
        } catch (IOException | UnrecoverableKeyException | CertificateException | KeyStoreException |
                 KeyManagementException | NoSuchAlgorithmException | JOSEException  e) {
            logger.log(Level.WARNING,e.getMessage());
        }


    }

}