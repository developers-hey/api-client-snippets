package com.heybanco.baas.client;

import com.heybanco.baas.client.util.SecurityManager;
import com.nimbusds.jose.shaded.gson.JsonObject;
import com.nimbusds.jose.shaded.gson.JsonParser;
import java.io.*;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.HashMap;
import java.util.Map;

import java.util.Properties;
import java.util.logging.*;

public class Client {
        private static final Logger logger = Logger.getLogger(Client.class.getName());
        private static final Properties properties = new Properties();
        private static final String B_APPLICATION_VALUE = "SUBSCRIPTION_B_APPLICATION";
        private static final String SUBSCRIPTION_CLIENT_ID = "SUBSCRIPTION_CLIENT_ID";
        private static final String SUBSCRIPTION_CLIENT_SECRET = "SUBSCRIPTION_CLIENT_SECRET";
        private static final String API_HOST_DNS = "API_HOST_DNS";
        private static final String API_BASE_PATH = "API_BASE_PATH";
        private static final String API_RESOURCE_NAME = "API_RESOURCE_NAME";
        private static final String TOKEN_HOST_DNS = "TOKEN_HOST_DNS";
        private static final String TOKEN_RESOURCE_NAME = "TOKEN_RESOURCE_NAME";
        private static final String TOKEN_AUTH_TYPE = "TOKEN_AUTH_TYPE";
        private static final String TOKEN_GRANT_TYPE = "TOKEN_GRANT_TYPE";
        private static final String REQUEST_HTTP_VERB = "REQUEST_HTTP_VERB";
        private static final String REQUEST_SEND_PAYLOAD = "REQUEST_SEND_PAYLOAD";
        private static final String REQUEST_UNENCRYPTED_PAYLOAD = "REQUEST_UNENCRYPTED_PAYLOAD";
        private  static  final  String B_TRANSACTION= "REQUEST_B_TRANSACTION";
        private  static  final  String REQUEST_B_OPTION= "REQUEST_B_OPTION";
        private  static  final  String MIME_TYPE= "REQUEST_MIME_TYPE";
        private  static  final  String ENCODE_CHARSET= "REQUEST_ENCODE_CHARSET";

        public static void main(String[] args) {

                String apiEndpoint = "";

                try {
                        try (FileInputStream input = new FileInputStream("../APIClient/src/main/resources/data.properties")) {
                                properties.load(input);
                        }

                        Map<String, String> headers = new HashMap<>();
                        headers.put("Accept", properties.getProperty(MIME_TYPE));
                        headers.put("Content-Type", properties.getProperty(MIME_TYPE));
                        headers.put("B-Transaction", properties.getProperty(B_TRANSACTION));
                        headers.put("B-Option", properties.getProperty(REQUEST_B_OPTION));
                        headers.put("Accept-Charset", properties.getProperty(ENCODE_CHARSET));
                        headers.put("B-application", properties.getProperty(B_APPLICATION_VALUE));
                        headers.put("Authorization", getToken());

                        apiEndpoint = properties.getProperty(API_HOST_DNS) + properties.getProperty(API_BASE_PATH) + properties.getProperty(API_RESOURCE_NAME);
                        doRequest(properties.getProperty(REQUEST_HTTP_VERB), apiEndpoint, properties.getProperty(REQUEST_UNENCRYPTED_PAYLOAD), headers, Boolean.parseBoolean(properties.getProperty(REQUEST_SEND_PAYLOAD)),true);

                } catch (Exception ex) {
                        logger.log(Level.WARNING, "Exception: ", ex);
                }
        }


        private static JsonObject doRequest(String httpVerb, String endpoint, String requestPayload, Map<String, String> headers, boolean sendPayload, boolean payloadEncryption) {
                logger.log(Level.INFO, "===============================================================");
                logger.log(Level.INFO, () -> "Request " + httpVerb + ": " + endpoint);
                logger.log(Level.INFO, () -> "Headers [" + headers + "]");
                JsonObject jsonResponse= null;
                SecurityManager securityManager = new SecurityManager(properties);

                int successResponse200 = 200;
                int successResponse201 = 201;
                String bTraceHeader = "b-trace";
                String locationHeader = "location";

                try {
                        HttpClient httpClient = HttpClient.newBuilder()
                                .sslContext(securityManager.getSSLContext())
                                .build();

                        if(sendPayload && payloadEncryption) {
                                requestPayload = securityManager.signAndEncryptPayload(properties.getProperty(REQUEST_UNENCRYPTED_PAYLOAD),
                                        properties.getProperty(B_APPLICATION_VALUE));
                        }

                        HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                                .uri(URI.create(endpoint))
                                .method(httpVerb, sendPayload ? HttpRequest.BodyPublishers.ofString(requestPayload) : HttpRequest.BodyPublishers.ofString(""));
                        headers.forEach(requestBuilder::header);

                        HttpResponse<String> response = httpClient.send(requestBuilder.build(), HttpResponse.BodyHandlers.ofString());

                        logger.log(Level.INFO, () -> "Response: " + response.statusCode());
                        jsonResponse = JsonParser.parseString(response.body()).getAsJsonObject();

                        if (payloadEncryption && response.statusCode() == successResponse200) {
                                Map<String, String> payload = new HashMap<>();
                                payload.put("code", jsonResponse.get("code").getAsString());
                                payload.put("message", jsonResponse.get("message").getAsString());
                                payload.put("data", securityManager
                                        .decryptAndVerifySignPayload(jsonResponse.get("data").getAsString()));
                                logger.log(Level.INFO, payload::toString);
                        } else {
                                logger.log(Level.INFO, response::body);
                        }

                        // Print relevant headers, for example: Locations contains the resource ID that have been created with POST
                        if (response.headers().firstValue(bTraceHeader).isPresent()) {
                                logger.log(Level.INFO,  () -> "Header [" + bTraceHeader + "=" + response.headers().allValues(bTraceHeader).toString() + "]");
                        }
                        if (response.statusCode() == successResponse201 && response.headers().firstValue(locationHeader).isPresent()) {
                                logger.log(Level.INFO, () -> "[" + locationHeader + "=" + response.headers().allValues(locationHeader).toString() + "]");
                        }

                } catch (Exception ex) {
                        logger.log(Level.WARNING, "Exception: ", ex);
                }

                logger.log(Level.INFO,"---------------------------------------------------------------");
                return jsonResponse;
        }


        private static String getToken() {
                logger.log(Level.INFO, "Generating token ...");
                String httpVerb = "POST";
                String ampersand = "&";
                String endpoint = properties.getProperty(TOKEN_HOST_DNS) + properties.getProperty(TOKEN_RESOURCE_NAME);

                Map<String, String> headers = new HashMap<>();
                headers.put("Content-Type", "application/x-www-form-urlencoded");
                StringBuilder payload = new StringBuilder("grant_type=")
                        .append(properties.getProperty(TOKEN_GRANT_TYPE))
                        .append(ampersand)
                        .append("client_id=")
                        .append(properties.getProperty(SUBSCRIPTION_CLIENT_ID))
                        .append(ampersand)
                        .append("client_secret=")
                        .append(properties.getProperty(SUBSCRIPTION_CLIENT_SECRET));

                JsonObject response = doRequest(httpVerb, endpoint, payload.toString(), headers, true, false);

                return properties.getProperty(TOKEN_AUTH_TYPE) + " " + response.get("access_token").getAsString();
        }

}