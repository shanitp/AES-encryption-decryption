package com.example;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.net.URISyntaxException;

/**
 * Main program which implements the AES
 * algorithm. This program will read in a file
 * containing the operation, mode, transmission size,
 * input text, key, and initialization vector. It will
 * then perform the AES algorithm on the input text
 * using the specified operation and mode. The result
 * will be returned with its operation type.
 */
public class AESImplementation {
    private int operation;
    private int mode;
    private String inputText, key, initilizationVector;
    private AES aes;

    public record AESResult(String result, String operationType) {}

    /**
     * This is the main method where the input will be scanned and any whitespace or junk character is removed
     * and formatted
     * @param args
     * @throws IOException
     * @throws URISyntaxException
     * @throws InterruptedException
     * @throws ClassNotFoundException
     * @throws NoSuchFieldException
     * @throws IllegalAccessException
     * @throws NoSuchMethodException
     * @throws InvocationTargetException
     * @throws InstantiationException
     * @throws IllegalArgumentException
     * @throws SecurityException
     * @throws Exception
     * @throws Throwable
     *
     *
     */
    public AESResult run(String operation, String transmissionSize, String inputText, String key, String initilizationVector) throws IOException, URISyntaxException, InterruptedException, ClassNotFoundException, NoSuchFieldException, IllegalAccessException, NoSuchMethodException, InvocationTargetException, InstantiationException, IllegalArgumentException, SecurityException {
        System.out.println("Reading in input file...");

        try {
            if (operation.isBlank() || transmissionSize.isBlank() || inputText.isBlank() || key.isBlank() || initilizationVector.isBlank()) {
                throw new IOException("Please provide the input file name");
            }
            this.operation = Integer.parseInt(operation);
            this.mode = 2;
            this.inputText = this.clean(inputText);
            this.key = this.clean( "00 E4 35 FF 01 35 78 91 AB CD 00 E4 67 F0 12 CF");
            this.initilizationVector = this.clean(initilizationVector);
        } catch (IOException ex) {
            System.out.println(ex.toString());
            throw ex;            
        }

        // Now we need to branch based on operation mode
        switch (this.mode) {
            case 0:
            case 1:
                // CFB or ECB
                System.out.println("Yet to Implement, Please provide option 2 as that is only available in this code");
                throw new IllegalArgumentException("Only CBC mode (option 2) is implemented");
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
        // The key will be in hex format and will be converted to bytes before being passed to the AES algorithm.
        this.aes.expansionKey = this.aes.keyExpansion(this.key);

        String result;
        String operationType;
        if (this.operation == 0) {
            System.out.println("Encrypting input...");
            result = this.aes.encrypt(this.inputText);
            operationType = "encrypted";
            System.out.println("Finished encrypting!");
        } else {
            System.out.println("Decrypting input...");
            result = this.aes.decrypt(this.inputText);
            operationType = "decrypted";
            System.out.println("Finished decrypting!");
        }
        
        return new AESResult(clean(result), operationType);
    }

    /**
     * Helper function to remove all whitespace from input
     */
    private String clean(String input) {
        return input.replaceAll("[\\s\\r\\n]*", "");
    }
}