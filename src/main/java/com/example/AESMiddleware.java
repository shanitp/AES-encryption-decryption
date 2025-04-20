package com.example;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Main program which implements the AES algorithm.
 * This program processes input containing operation mode,
 * input text, key, and initialization vector. It performs 
 * the AES algorithm on the input text using the specified 
 * operation mode.
 */
public class AESMiddleware {
    private int operation;
    private int mode;
    private String inputText, key, initilizationVector;
    private AES aes;

    private static final String CONSTANT_KEY = "00 E4 35 FF 01 35 78 91 AB CD 00 E4 67 F0 12 CF";
    private static final String CONSTANT_IV = "fe a2 25 a2 20 75 eb 89 2d 0b f3 18 b2 2e 1d ce";

    public String processInput(String content, String operationType, String transmissionSize, String mode) {
        String result = "";
        try {
            this.operation = Integer.parseInt(operationType);
            this.mode = Integer.parseInt(mode);
            this.inputText = this.clean(content);
            this.key = this.clean(CONSTANT_KEY);
            this.initilizationVector = this.clean(CONSTANT_IV);

            // Validate operation
            if(this.operation < 0 || this.operation > 1) {
                throw new IllegalArgumentException("Invalid operation - must be 0 for encryption or 1 for decryption");
            }

            // Validate mode
            if(this.mode != 2) {
                throw new IllegalArgumentException("Only CBC mode (2) is currently supported");
            }

            // Now we need to branch based on operation mode
            switch (this.mode) {
                case 2:
                    // CBC
                    this.aes = new CBC();
                    // Parse IV
                    this.aes.parseInitializationVector(this.initilizationVector);
                    break;
                default:
                    throw new IllegalArgumentException("Invalid mode selected");
            }

            // Expand Key
            this.aes.expansionKey = this.aes.keyExpansion(this.key);

            // Perform encryption/decryption
            if (this.operation == 0) {
                // Add padding for encryption
                // String paddedInput = Utils.padHexString(this.inputText);
                result = this.aes.encrypt(this.inputText);
            } else {
                // For decryption, input should already be properly padded
                if (this.inputText.length() % 32 != 0) {
                    throw new IllegalArgumentException("Invalid input length for decryption - must be multiple of 32 hex chars");
                }
                result = this.aes.decrypt(this.inputText);
            }

            return clean(result);

        } catch (Exception ex) {
            throw new IllegalArgumentException("Failed to process input: " + ex.getMessage());
        }
    }

    /**
     * Helper function to remove all whitespace from input
     */
    private String clean(String input) {
        return input.replaceAll("[\\s\\r\\n]*", "");
    }
}