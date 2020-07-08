package com.mnzit.hmac.demo.dto;

import java.io.Serializable;
import lombok.Getter;
import lombok.Setter;

/**
 *
 * @author Manjit Shakya <mnzitshakya@gmail.com>
 */
@Getter
@Setter
public class ServerResponse implements Serializable {

    private Boolean success;
    private String description;
    private Object object;

    public ServerResponse(Boolean success, String description) {
        this.success = success;
        this.description = description;
    }

    public ServerResponse(Boolean success) {
        this.success = success;
    }

    public ServerResponse(Boolean success, Object object) {
        this.success = success;
        this.object = object;
    }

    public ServerResponse(Boolean success, String description, Object object) {
        this.description = description;
        this.success = success;
        this.object = object;
    }

    public static ServerResponse buildSuccess(Object object) {
        return new ServerResponse(true, object);
    }

    public static ServerResponse buildSuccess(String description, Object object) {
        return new ServerResponse(true, description, object);
    }

    public static ServerResponse buildFailure() {
        return new ServerResponse(false);
    }

    public static ServerResponse buildSuccess() {
        return new ServerResponse(true);
    }

    public static ServerResponse build(ServerResponse serverResponse, Boolean success) {
        serverResponse.setSuccess(success);
        return serverResponse;
    }

    public static ServerResponse buildFailure(String description) {
        return new ServerResponse(false, description);
    }
}
