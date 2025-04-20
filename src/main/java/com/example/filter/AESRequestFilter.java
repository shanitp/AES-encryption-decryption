package com.example.filter;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.BufferedReader;
import java.io.IOException;

import org.json.JSONObject;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import com.example.AESMiddleware;
import org.springframework.web.filter.OncePerRequestFilter;
import com.example.Utils;

@Component
public class AESRequestFilter extends OncePerRequestFilter {

    public String getPostBody(HttpServletRequest request) throws IOException {
        StringBuilder body = new StringBuilder();
        try (BufferedReader reader = request.getReader()) {
            String line;
            while ((line = reader.readLine()) != null) {
                body.append(line);
            }
        }
        return body.toString();
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) 
            throws ServletException, IOException {
        
        if ("POST".equalsIgnoreCase(request.getMethod())) {
            String postBodyRaw = getPostBody(request);

            try {
                // Convert text to properly padded hex
                //postBody = Utils.stringToHex(postBody);
                String finalPostBody = postBodyRaw;
                if (
                    request.getRequestURL().toString().contains("encrypt") || 
                    request.getRequestURL().toString().contains("decrypt")
                ) {
                    System.out.println("Encrypting request body");
                } else {
                    String key = request.getHeader("X-encrypt-key");
                    AESMiddleware aESEncrypter = new AESMiddleware();
                    String decryptedContent = aESEncrypter.processInput(postBodyRaw, "1", "0", "2", key);
                    String decryptedText = Utils.hexToText(decryptedContent);
                    JSONObject jsonObj = new JSONObject(decryptedText);
                    finalPostBody = jsonObj.toString();                
                }
                ModifiedRequestWrapper modifiedRequest = new ModifiedRequestWrapper(request, finalPostBody);
                filterChain.doFilter(modifiedRequest, response);
            } catch (Exception e) {
                response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                String errorMessage = "Failed to process decryption request: " + e.getMessage();
                System.out.println(errorMessage);
                e.printStackTrace();
                response.getWriter().write(errorMessage);
            }
        } else {
            filterChain.doFilter(request, response);
        }
    }
}