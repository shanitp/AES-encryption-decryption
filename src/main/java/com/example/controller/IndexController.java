package com.example.controller;

import java.io.StringWriter;

import org.json.JSONObject;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.http.ResponseEntity;
import org.springframework.http.MediaType;

import com.example.AESMiddleware;
import com.example.Utils;
import com.example.model.MessageRequest;
import com.example.model.MessageResponse;
import com.fasterxml.jackson.databind.ObjectMapper;

@RestController
public class IndexController {
    
    @GetMapping("/index")
    public String index() {
        return "Hello world";
    }

    @PostMapping(value = "/index", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> postMessage(@RequestBody MessageRequest request) {
        try {
            String newMessage = "We received your message: " + request.getMessage();
            MessageResponse msg = new MessageResponse(
                newMessage
            );
            String msgStr = new ObjectMapper().writeValueAsString(msg);
            String encryptedContent = Utils.encript(msgStr);
            return ResponseEntity.ok(encryptedContent);
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                .body(e.getMessage());
        }
    }

    @PostMapping(value = "/encrypt", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> postMessageEncrypt(@RequestBody MessageRequest request) {
        try {
            MessageResponse msg = new MessageResponse(
                request.getMessage()
            );

            String msgStr = new ObjectMapper().writeValueAsString(msg);
            String encryptedContent = Utils.encript(msgStr);
            return ResponseEntity.ok(encryptedContent);
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                .body(e.getMessage());
        }
    }

    @PostMapping(value = "/decrypt", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> postMessageDecrypt(@RequestBody String request) {
        try {
            AESMiddleware aESEncrypter = new AESMiddleware();
            String msgStr = request.toString();

            String decryptedContent = aESEncrypter.processInput(msgStr, "1", "0", "2");
            String encryptedText = Utils.hexToText(decryptedContent);
            JSONObject jsonObj = new JSONObject(encryptedText);
            return ResponseEntity.ok(jsonObj.toString());
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                .body(new JSONObject(e.getMessage()).toString());
        }
    }
}