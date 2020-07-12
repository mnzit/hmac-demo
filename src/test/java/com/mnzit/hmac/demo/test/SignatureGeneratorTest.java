package com.mnzit.hmac.demo.test;

import com.mnzit.hmac.demo.util.SignatureBuilder;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import lombok.extern.slf4j.Slf4j;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 *
 * @author Manjit Shakya <mnzitshakya@gmail.com>
 */
@Slf4j
public class SignatureGeneratorTest {

    @Before
    public void start() {
        log.info("============SignatureGeneratorTests START============");
    }

    @After
    public void end() {
        log.info("============SignatureGeneratorTests END============");
    }

    @Test
    public void generateSignature() throws URISyntaxException {
        String uuid = UUID.randomUUID().toString();
        String unixTime = String.valueOf(System.currentTimeMillis() / 1000L);
        String applicationUserId = "Manjit";
        String path = "/login?name=manjit&age=10";
        URI uri = new URI(path);

        String query = uri.getRawQuery();
        
        log.debug("query : {}",query);

        SignatureBuilder signatureBuilder = new SignatureBuilder()
                .method("POST")
                .path("/login?name=manjit&age=10")
                .body("Manjit")
                .contentType("application/json")
                .username(applicationUserId)
                .nonce(uuid)
                .timestamp(unixTime)
                .secret("theSecret");

        String signature = signatureBuilder.buildSignatureBase64Encoded();

        String header = "HMAC " + applicationUserId + ":" + uuid + ":" + signature;

        log.info("X-Authorization: {}", header);

        log.info("X-Authorization-Timestamp : {}", unixTime);
    }

    @Test
    public void encodeURL() throws UnsupportedEncodingException {
        String url = "https://www.f1soft.com/home?";

        Map<String, String> requestParams = new HashMap<>();
        requestParams.put("key1", "value 1");
        requestParams.put("key2", "value@!$2");
        requestParams.put("key3", "value%3");

//        String encodedURL = requestParams.keySet().stream()
//                .map(key -> key + "=" + URLEncoder.encode(requestParams.get(key), StandardCharsets.UTF_8.toString()))
//                .collect(joining("&", url, ""));
//        log.info("Encoded URL: {}", encodedURL);
//
//URI uri = new URI(testUrl);
// 
//    String scheme = uri.getScheme();
//    String host = uri.getHost();
//    String query = uri.getRawQuery();
// 
//    String decodedQuery = Arrays.stream(query.split("&"))
//      .map(param -> param.split("=")[0] + "=" + decode(param.split("=")[1]))
//5      .collect(Collectors.joining("&"));
    }
}
