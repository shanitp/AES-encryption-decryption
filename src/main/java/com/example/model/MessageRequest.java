package com.example.model;

public class MessageRequest {
    private String message;

    // Default constructor needed for JSON deserialization
    public MessageRequest() {}

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }
}