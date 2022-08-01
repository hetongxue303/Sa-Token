package com.hetongxue.common.response;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.experimental.Accessors;

import java.io.Serializable;

/**
 * @Description: 统一返回类
 * @ClassNmae: Result
 * @Author: 何同学
 * @DateTime: 2022-08-01 13:57
 */
@Data
@AllArgsConstructor
@Accessors(chain = true)
public class Result implements Serializable {

    // 状态码
    private Integer code;
    // 状态消息
    private String message;
    // 结果数据
    private Object data;

    private Result() {
    }

    /**
     * 成功返回
     **/
    public static Result Success() {
        return new Result()
                .setCode(ResponseCode.OK.getCode())
                .setMessage(ResponseCode.OK.getMessage());
    }

    public static Result Success(Object data) {
        return new Result()
                .setCode(ResponseCode.OK.getCode())
                .setMessage(ResponseCode.OK.getMessage())
                .setData(data);
    }

    /**
     * 失败返回
     **/
    public static Result Error() {
        return new Result()
                .setCode(ResponseCode.BAD_REQUEST.getCode())
                .setMessage(ResponseCode.BAD_REQUEST.getMessage());
    }

    public static Result Error(Object data) {
        return new Result()
                .setCode(ResponseCode.BAD_REQUEST.getCode())
                .setMessage(ResponseCode.BAD_REQUEST.getMessage())
                .setData(data);
    }

}