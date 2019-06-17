package com.network.analysis.entity;

import java.io.Serializable;

/**
 * Created by Garlan on 2019/6/1.
 */
public class Return<T> implements Serializable {
    public static final long serialVersionUID = 1L;

    // 成功
    public static final Return<String> SUCCESS = new Return<>();

    // 服务器错误
    public static final Return<String> SERVER_ERROR = new Return<>(300, "服务器错误！");

    private int code;
    private String msg;
    private T data;

    public Return() {
        this.code = 100;
    }

    public Return(int code, String msg) {
        this.code = code;
        this.msg = msg;
    }

    public Return(T data) {
        this.code = 100;
        this.data = data;
    }

    public int getCode() {
        return code;
    }

    public void setCode(int code) {
        this.code = code;
    }

    public String getMsg() {
        return msg;
    }

    public void setMsg(String msg) {
        this.msg = msg;
    }

    public T getData() {
        return data;
    }

    public void setData(T data) {
        this.data = data;
    }

}