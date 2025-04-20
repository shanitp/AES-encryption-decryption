package com.example;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Main class which implements the AES algorithm.
 * This class is used to run the AES algorithm
 * in different modes and operations.
 * It reads in a file containing the operation,
 * mode, transmission size, input text, key,
 *  and initialization vector.
 * It then performs the AES algorithm on the input text
 * using the specified operation and mode.
 * The result is printed to the console.   
 * 
 */
@SpringBootApplication
public class Main {
    public static void main(String[] args) {
        SpringApplication.run(Main.class, args);
    }
}