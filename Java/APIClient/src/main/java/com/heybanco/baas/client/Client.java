package com.heybanco.baas.client;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.shaded.gson.JsonObject;
import com.nimbusds.jose.shaded.gson.JsonParser;
import java.io.*;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
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

import java.util.Optional;
import java.util.Properties;
import java.util.logging.*;

public class Client {
        private static final Logger logger = Logger.getLogger(Client.class.getName());
        private static final String HOSTNAME_VALUE = "HOSTNAME";
        private static final String B_APPLICATION_VALUE = "B_APPLICATION";
        private static final String BASE_PATH = "/taas/v1.0";
        private static final String ENDPOINT = "/accounts";

        public static void main(String[] args) {
                Properties properties = new Properties();
                String method = "POST";
                SecurityManager securityManager = new SecurityManager(properties);
                try {
                        logger.log(Level.INFO, "Leyendo properties" );

                        FileInputStream input = new FileInputStream("../APIClient/src/main/resources/config.properties");
                        properties.load(input);
                        input.close();
                        JsonObject jsonResponse = JsonParser.parseString(securityManager.getAuthorizationToken())
                                        .getAsJsonObject();
                        String accessToken = jsonResponse.get("access_token").getAsString();
                        logger.log(Level.INFO, "Se obtuvo el Token: " + accessToken);
                        Map<String, String> headers = new HashMap<String, String>() {
                        };
                        headers.put("Accept", "application/json");
                        headers.put("Content-Type", "application/json");
                        headers.put("B-Transaction", "123456789");
                        headers.put("Accept-Charset", "UTF-8");
                        headers.put("B-application", properties.getProperty(B_APPLICATION_VALUE));
                        headers.put("Authorization", "Bearer " + accessToken);
                        String requestPayload = "{\"customerId\":\"4367c480-66d3-11ed-8ff8-0050568a58c8\",\"recipientAccounts\":[{\"accountNumber\":\"8116453756\",\"accountType\":1,\"financialEntityId\":\"002\",\"beneficiaryName\":\"Luis Alvarez\",\"alias\":\"Amigo\",\"beneficiaryRFC\":\"AAXL881128H40\",\"email\":\"ejemplo@banregio.com\"}]}";
                        String encryptedPayload = securityManager.signAndEncryptPayload(requestPayload,
                                        properties.getProperty(B_APPLICATION_VALUE));
                        requestPayload = "{\"data\":\"" + encryptedPayload + "\"}";
                        HttpClient httpClient = HttpClient.newBuilder()
                                        .sslContext(securityManager.getSSLContext())
                                        .build();
                        HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                                        .uri(URI.create((properties.getProperty(HOSTNAME_VALUE) + BASE_PATH
                                                        + ENDPOINT)))
                                        .method(method, HttpRequest.BodyPublishers.ofString(requestPayload));
                        headers.forEach(requestBuilder::header);
                        HttpResponse<String> response = httpClient.send(requestBuilder.build(),
                                        HttpResponse.BodyHandlers.ofString());
                        String responseHeaders = response.headers().map().toString();
                        String responseBody = response.body();
                        logger.log(Level.INFO, "Response headers: " + responseHeaders);
                        logger.log(Level.INFO, "Response body: " + responseBody);
                        Optional<String> locationHeader = response.headers().firstValue("location");

                        if (locationHeader.isPresent()) {
                                requestBuilder = HttpRequest.newBuilder()
                                                .uri(URI.create((properties.getProperty(HOSTNAME_VALUE) + BASE_PATH
                                                                + locationHeader.get())))
                                                .GET();
                                headers.remove("Content-Type");
                                headers.forEach(requestBuilder::header);
                                HttpResponse<String> responseEncript = httpClient.send(requestBuilder.build(),
                                                HttpResponse.BodyHandlers.ofString());
                                String responseBodyEncrypt = responseEncript.body();
                                logger.log(Level.INFO, "Response body encrypted: " + responseBodyEncrypt);
                                jsonResponse = JsonParser.parseString(responseBodyEncrypt).getAsJsonObject();
                                String decryptedPayload = securityManager
                                                .decryptAndVerifySignPayload(jsonResponse.get("data").getAsString());
                                logger.log(Level.INFO, "Decrypted response body: " + decryptedPayload);
                        }
                } catch (IOException | UnrecoverableKeyException | CertificateException | KeyStoreException
                                | KeyManagementException | NoSuchAlgorithmException | JOSEException | URISyntaxException
                                | ParseException e) {
                        logger.log(Level.WARNING, e.getMessage());
                } catch (InterruptedException ie) {
                        logger.log(Level.WARNING, "The thread has been interrupted  " + ie.getMessage());
                        Thread.currentThread().interrupt();
                }

        }

}