package com.example;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.net.URISyntaxException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Scanner;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.net.URL;

/**
 * Main program which implements the AES
 * algorithm. This program will read in a file
 * containing the operation, mode, transmission size,
 * input text, key, and initialization vector. It will
 * then perform the AES algorithm on the input text
 * using the specified operation and mode. The result
 * will be printed to the console.
 * 
 */
public class AESImplementation {
    private int operation;
    private int mode;
    private int transmissionSize;
    private String inputText, key, initilizationVector;
    private Scanner console;
    private AES aes;
    private String filename;

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
    public void run(String[] input) {
        console = new Scanner(System.in);

        System.out.println("Reading in input file...");

        try {
            for (String file : input) {
                filename = file;
                String content = readFile("./" + filename, StandardCharsets.UTF_8);

                String regex = "[\\r\\n]*(?<OPERATION>[\\d])[\\r\\n]+(?<MODE>[\\d])[\\r\\n]+(?<TRANSMISSIONSIZE>[\\d]+)[\\r\\n]+(?<INPUT>[0-9A-Fa-f\\s]{64,95})[\\r\\n]+(?<KEY>[0-9A-Fa-f\\s]{32,47})[\\r\\n]+(?<INITIALIZATIONVECTOR>[0-9A-Fa-f\\s]{32,47})";
                Pattern p = Pattern.compile(regex);
                Matcher m = p.matcher(content);

                while(m.find()) {
                    this.operation = Integer.parseInt(m.group("OPERATION"));
                    this.mode = Integer.parseInt(m.group("MODE"));
                    this.transmissionSize = Integer.parseInt(m.group("TRANSMISSIONSIZE"));
                    this.inputText = this.clean(m.group("INPUT"));
                    this.key = this.clean(m.group("KEY"));
                    this.initilizationVector = this.clean(m.group("INITIALIZATIONVECTOR"));
                }

                // Perform some quick validation
                while(this.operation < 0 || this.operation > 1) {
                    System.out.println("Invalid input of encryption/decryption, please enter 0 for encryption, 1 for decryption or 99 to exit the program.");
                    this.operation = console.nextInt();

                    // Exit on 99
                    if (this.operation == 99)
                        System.exit(0);
                }
                while(this.mode < 0 || this.mode > 3) {
                    System.out.println("Invalid mode selection, please enter a value from the list below, or 99 to exit:");
                    System.out.println("0 - ECB");
                    System.out.println("1 - CFB");
                    System.out.println("2 - CBC");
                    this.mode = console.nextInt();

                    // Exit on 99
                    if (this.mode == 99)
                        System.exit(0);
                }
            }
        } catch (IOException ex) {
            System.out.println(ex.toString());
            System.exit(0);
        }

        // Now we need to branch based on operation mode
        switch (this.mode) {
            case 0:
            case 1:
                // CFB or ECB
                System.out.println("Yet to Implement, Please provide option 2 as that is only available in this code");
                break;
            case 2:
                // CBC
                this.aes = new CBC();
                // Parse IV
                this.aes.parseInitializationVector(this.initilizationVector);
                break;
            default:
                break;
        }

        // Expand Key
        // The key will be in hex format and will be converted to bytes before being passed to the AES algorithm.
        this.aes.expansionKey = this.aes.keyExpansion(this.key);

  
        /**
         * The encrypt/decrypt function will take the input text and key and
         * initialization vector and perform the AES algorithm on it. The result
         * will be printed to the console. The input text will be in hex format
         * and will be converted to bytes before being passed to the AES algorithm.
         * The key and initialization vector will also be in hex format and will
         * be converted to bytes before being passed to the AES algorithm. 
         */
        String result;
        if (this.operation == 0) {
            System.out.println("Encrypting input...");
            result = this.aes.encrypt(this.inputText);
            System.out.println("Finished encrypting!");
            System.out.println("The encrypted string is " + clean(result));
        } else {
            System.out.println("Decrypting input...");
            result = this.aes.decrypt(this.inputText);
            System.out.println("Finished decrypting!");
            System.out.println("The decrypted string is " + clean(result));
        }
    }

    /**
     * Helper function to read in file
     * @param path
     * @param encoding
     * @return
     * @throws IOException
     * @throws URISyntaxException
     * @throws Exception
     * @throws Throwable
     * 
     */
    private static String readFile(String path, Charset encoding) throws IOException {
        URL resourceUrl = AESImplementation.class.getClassLoader().getResource(path);
        if (resourceUrl == null) {
            throw new IOException("File not found in classpath: " + path);
        }
    
        try {
            return new String(Files.readAllBytes(Paths.get(resourceUrl.toURI())), encoding);
        } catch (URISyntaxException e) {
            throw new IOException("Invalid URI syntax for resource: " + path, e);
        }
    }
    


    /**
     * Helper function to remove all whitespace from input
     */
    private String clean(String input) {
        return input.replaceAll("[\\s\\r\\n]*", "");
    }
}