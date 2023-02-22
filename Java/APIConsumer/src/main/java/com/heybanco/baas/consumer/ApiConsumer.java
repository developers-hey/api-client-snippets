package com.heybanco.baas.consumer;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.shaded.gson.JsonObject;
import com.nimbusds.jose.shaded.gson.JsonParser;

import java.io.*;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
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

public class ApiConsumer {
    private static final Logger logger = Logger.getLogger(ApiConsumer.class.getName());
    private static final String HOSTNAME = "https://test-tech.hey.inc";
    private static final String CLIENT_ID = "bank-app";
    private static final String CLIENT_SECRET = "abf3714d-1a00-4b1e-9ad4-7d4554105c7c";
    private static final String B_APPLICATION = "abf3714d-1a00-4b1e-9ad4-7d4554105c7c";

    public static void main(String[] args) {
        Properties prop = new Properties();
        FileInputStream input = null;
        String method = "POST";
        String endpoind = "/api/taas/v1.0/accounts";
        SecurityManager securityManager = new SecurityManager(prop);
        try {
            input = new FileInputStream("../APIConsumer/src/main/resources/config.properties");
            prop.load(input);
            JsonObject jsonResponse = JsonParser
                    .parseString(securityManager.getAuthorizationToken(CLIENT_ID, CLIENT_SECRET)).getAsJsonObject();
            String accessToken = jsonResponse.get("access_token").getAsString();
            Map<String, String> headers = new HashMap<String, String>() {
            };
            headers.put("Accept", "application/json");
            headers.put("Content-Type", "application/json");
            headers.put("B-Transaction", "123456789");
            headers.put("Accept-Charset", "UTF-8");
            headers.put("B-application", B_APPLICATION);
            headers.put("Authorization", "Bearer " + accessToken);
            String requestPayload = "{\"taxRegimeId\": 2,\"name\": \"Jose Luis\",\"lastName\": \"Lemuus\",\"secondLastName\": \"Valdivia\",\"businessName\": \"\",\"birthday\": \"1996-10-03\",\"rfc\": \"LEVL961003KQ0\",\"curp\": \"LEVL961003HBSMLS06\",\"callingCode\": \"52\",\"cellPhoneNumber\": \"3311065681\",\"email\": \"jose.lemus@banregio.com\",\"nationalityId\": \"001\",\"countryId\": \"01\",\"stateId\": \"047\",\"cityId\": \"04701005\",\"legalRepresentative\": {\"name\": \"\",\"lastName\": \"\",\"secondLastName\": \"\"}}";
            String encryptedPayload = securityManager.signAndEncryptPayload(requestPayload, B_APPLICATION);
            requestPayload = "{\"data\":\"" + encryptedPayload + "\"}";
            HttpClient httpClient = HttpClient.newBuilder()
                    .sslContext(securityManager.getSSLContext())
                    .build();
            HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                    .uri(URI.create((HOSTNAME + endpoind)))
                    .method(method, HttpRequest.BodyPublishers.ofString(requestPayload));
            headers.forEach(requestBuilder::header);
            HttpResponse<String> response = httpClient.send(requestBuilder.build(),
                    HttpResponse.BodyHandlers.ofString());
            String locationHeader = response.headers().firstValue("location").orElse(null);
            String accountId = locationHeader.replace("/accounts", "");
            logger.log(Level.INFO, response.headers().map().toString());
            logger.log(Level.INFO, response.body());
            requestBuilder = HttpRequest.newBuilder()
                    .uri(URI.create((HOSTNAME + endpoind + accountId)))
                    .GET();
            headers.remove("Content-Type");
            headers.forEach(requestBuilder::header);
            HttpResponse<String> responseEncript = httpClient.send(requestBuilder.build(),
                    HttpResponse.BodyHandlers.ofString());
            logger.log(Level.INFO, responseEncript.body());
            jsonResponse = JsonParser.parseString(responseEncript.body()).getAsJsonObject();
            logger.log(Level.INFO, securityManager.decryptAndVerifySignPayload(jsonResponse.get("data").getAsString()));

        } catch (IOException | UnrecoverableKeyException | CertificateException | KeyStoreException
                | KeyManagementException | NoSuchAlgorithmException | JOSEException | InterruptedException
                | URISyntaxException | ParseException e) {
            logger.log(Level.WARNING, e.getMessage());
        }

    }

}