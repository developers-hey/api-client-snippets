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
        private static final String HOSTNAME_VALUE = "HOSTNAME.DNS";
        private static final String B_APPLICATION_VALUE = "B.APPLICATION";
        private static final String BASE_PATH_VALUE = "BASE.PATH";
        private static final String ENDPOINT_VALUE = "URI.NAME";
        private static final String UNENCRYPTED_PAYLOAD = "UNENCRYPTED.PAYLOAD";
        private  static  final  String B_TRANSACTION= "B.TRANSACTION";
        private  static  final  String B_OPTION= "B.OPTION";
        private  static  final  String MIME_TYPE= "MIME.TYPE";
        private  static  final  String ENCODE_CHARSET= "ENCODE.CHARSET";

        public static void main(String[] args) {
                Properties properties = new Properties();

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
                        String method = "HTTP.VERB";
                        Map<String, String> headers = new HashMap<String, String>() {
                        };
                        headers.put("Accept", properties.getProperty(MIME_TYPE));
                        headers.put("Content-Type", properties.getProperty(MIME_TYPE));
                        headers.put("B-Transaction", properties.getProperty(B_TRANSACTION));
                        headers.put("Accept-Charset", properties.getProperty(ENCODE_CHARSET));
                        headers.put("B-application", properties.getProperty(B_APPLICATION_VALUE));
                        headers.put("Authorization", "Bearer " + accessToken);

                        String encryptedPayload = securityManager.signAndEncryptPayload(properties.getProperty(UNENCRYPTED_PAYLOAD),
                                        properties.getProperty(B_APPLICATION_VALUE));
                        String requestEncryptedPayload = "{\"data\":\"" + encryptedPayload + "\"}";
                        HttpClient httpClient = HttpClient.newBuilder()
                                        .sslContext(securityManager.getSSLContext())
                                        .build();
                        HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                                        .uri(URI.create((properties.getProperty(HOSTNAME_VALUE) + BASE_PATH_VALUE
                                                        + ENDPOINT_VALUE)))
                                        .method(method, HttpRequest.BodyPublishers.ofString(requestEncryptedPayload));
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
                                                .uri(URI.create((properties.getProperty(HOSTNAME_VALUE) + BASE_PATH_VALUE
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