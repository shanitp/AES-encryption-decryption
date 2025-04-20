package com.example;

/**
 * This abstract class contains the method that is needed to run in
 * order to perform AES encryption and decryption.
 * It contains the methods for key expansion, add round key, mix columns,
 * shift rows, inverse shift rows, substitute bytes, and inverse substitute bytes.
 * It also contains the method to parse the initialization vector and
 * convert the state to a string.
 * The class also contains the abstract methods for encryption and decryption.
 * The class is extended by the AES_ECB and AES_CBC classes which implement
 * the encryption and decryption methods.
 * The class also contains the initialization vector which is used in the CBC mode of operation.
 * The class also contains the expansion key which is used in the encryption and decryption process.
 * The class also contains the S-Box and inverse S-Box which are used in the substitution process.
 * The class also contains the Galois multiplication tables which are used in the mix columns process.
 * The class also contains the round constants which are used in the key expansion process.
 * The class also contains the mix columns and inverse mix columns tables which are used in the mix columns process.
 */
public abstract class AES {
    protected int[][] expansionKey;
    protected int[][] initializationVector = new int[4][4];

    /**
     * This method does the Key expansion process which will send the expanded key to subsequent rounds.
     * This method takes input as String and outputs a 2 * 2 integer matrix.
     * The key is parsed into a 4x4 matrix and then expanded to 44 keys.
     * The key is expanded by using the g function which rotates the word and substitutes the bytes with Sbox values.
     * The g function is called for every 4th word and the result is XORed with the previous word.
     * The key is expanded by using the rcon values which are used to XOR the first byte of the word.
     * The key is expanded by using the Sbox values which are used to substitute the bytes of the word.
     * The key is expanded by using the galois multiplication tables which are used to multiply the bytes of the word.
     * The key is expanded by using the mix columns and inverse mix columns tables which are used to mix the columns of the word.
     * The key is expanded by using the round constants which are used to XOR the first byte of the word.
     *
     * @param key
     * @output expandedKey
     */
    protected int[][] keyExpansion(String key) {
        // Set number of keys we need - 10 keys x 4 bytes + initial
        int keySize = 44;
        int index = 1;
        int[][] expandedKey = new int[4][keySize];
        // Parsing key into 4x4 matrix
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                expandedKey[j][i] = Integer.parseInt(key.substring((8 * i) + (2 * j), (8 * i) + (2 * j + 2)), 16);
            }
        }

        // Set start point - given we have already filled the first key
        int initialPosition = 4;
        int[] tempArray = new int[4];
        int b;
        while (initialPosition < keySize) {
            if (initialPosition % 4 == 0) {
                // Copy the last word to temp array
                for (b = 0; b < 4; b++) {
                    tempArray[b] = expandedKey[b][initialPosition - 1];
                }
                // Go through g
                tempArray = gFunction(tempArray, index++);
                // Perform XOR operation
                for (b = 0; b < 4; b++) {
                    expandedKey[b][initialPosition] = tempArray[b] ^ expandedKey[b][initialPosition - 4];
                }
            } else {
                for (b = 0; b < 4; b++) {
                    expandedKey[b][initialPosition] = expandedKey[b][initialPosition - 1] ^ expandedKey[b][initialPosition - 4];
                }
            }
            initialPosition++;
        }

        return expandedKey;
    }

    /**
     * A helper function which is called by keyExpansion().
     *
     * The purpose of this function is to rotate the word for every 4th word and
     * substitute the bytes with Sbox values.
     * The function takes the last word of the key and rotates it.
     * The function then substitutes the bytes with Sbox values.
     * The function then XORs the first byte of the word with the rcon value.
     * The function then returns the new word.
     * The function is called for every 4th word and the result is XORed with the previous word.
     *
     * @param a
     */
    private int[] gFunction(int[] a, int index) {
        int[] tmp = new int[4];

        // Rotate similar to shift rows
        tmp[0] = a[1];
        tmp[1] = a[2];
        tmp[2] = a[3];
        tmp[3] = a[0];

        // Substitute with sBox
        int val;

        for (int i = 0; i < 4; i++) {
            val = tmp[i];
            tmp[i] = Utils.sbox[val / 16][val % 16];
        }
        // Finally XOR with rcon
        tmp[0] ^= Utils.rcon[index];

        return tmp;
    }

    /**
     * Adds round key to state by performing XOR operation.
     * The round key is obtained from the expanded key.
     * The round key is obtained by taking the first 4 bytes of the expanded key.
     */
    protected int[][] addRoundKey(int[][] state, int round) {
        int[][] roundKey = new int[4][4];
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                roundKey[i][j] = this.expansionKey[i][(4 * round) + j];
            }
        }

        // Perform XOR between state and round key
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                state[i][j] ^= roundKey[i][j];
            }
        }

        return state;
    }

    /**
     * Mix columns via galois multiplication
     *
     * Using galois multiplication each byte is transformed. This is done by using the multiplication look up table created in Utils.class
     * Based on the byte position, the lookup index is defined and  comparison is done with galois constant array
     */
    protected int[][] mixColumns(int[][] state, String operation) {
        int[][] tmp = new int[4][4];
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                int val = 0;

                for (int k = 0; k < 4; k++) {
                    int g = (operation == Utils.ENCRYPTION) ? Utils.mix_Columns[i][k]: Utils.inverse_Mix_Columns[i][k];
                    int s = state[k][j];
                    if (g == 1) {
                        val = val ^ s;
                    }
                    if(operation.equals(Utils.ENCRYPTION)){
                        if (g == 2) {
                            val = val ^ Utils.mc2[s / 16][s % 16];
                        } else if (g == 3) {
                            val = val ^ Utils.mc3[s / 16][s % 16];
                        } else {
                            val = val ^ 0;
                        }
                    }  else {
                        if (g == 9) {
                            val = val ^ Utils.mc9[s / 16][s % 16];
                        } else if (g == 11) {
                            val = val ^ Utils.mc11[s / 16][s % 16];
                        } else if (g == 13) {
                            val = val ^ Utils.mc13[s / 16][s % 16];
                        } else if (g == 14) {
                            val = val ^ Utils.mc14[s / 16][s % 16];
                        } else {
                            val = val ^ 0;
                        }
                    }
                }
                tmp[i][j] = val;
            }
        }

        return tmp;
    }

    /**
     * Shifts rows in state for encryption
     *
     * Row 0 is left untouched
     * Row 1 shifts 1 left
     * Row 2 shifts 2 left
     * Row 3 shifts 3 left
     */
    protected int[][] shiftRowsForEncryption(int[][] state) {
        int[][] tmp = new int[4][4];

        // No change in row 0
        tmp[0][0] = state[0][0];
        tmp[0][1] = state[0][1];
        tmp[0][2] = state[0][2];
        tmp[0][3] = state[0][3];

        // Shift row 1 left 1 position
        tmp[1][0] = state[1][1];
        tmp[1][1] = state[1][2];
        tmp[1][2] = state[1][3];
        tmp[1][3] = state[1][0];

        // Shift row 2 left 2 positions
        tmp[2][0] = state[2][2];
        tmp[2][1] = state[2][3];
        tmp[2][2] = state[2][0];
        tmp[2][3] = state[2][1];

        // Shift row 3 left 3 positions
        tmp[3][0] = state[3][3];
        tmp[3][1] = state[3][0];
        tmp[3][2] = state[3][1];
        tmp[3][3] = state[3][2];

        return tmp;
    }

    /**
     * Shifts rows in state for decryption
     *
     * Row 0 is left untouched
     * Row 1 shifts 1 untouched
     * Row 2 shifts 2 untouched
     * Row 3 shifts 3 untouched
     */
    protected int[][] inverseShiftRowsForDecryption(int[][] state) {
        // Init temp matrix
        int[][] tmp = new int[4][4];

        // Row 0 will not be changed
        tmp[0][0] = state[0][0];
        tmp[0][1] = state[0][1];
        tmp[0][2] = state[0][2];
        tmp[0][3] = state[0][3];

        // Shift row 1 right 1 position
        tmp[1][0] = state[1][3];
        tmp[1][1] = state[1][0];
        tmp[1][2] = state[1][1];
        tmp[1][3] = state[1][2];

        // Shift row 2 right 2 positions
        tmp[2][0] = state[2][2];
        tmp[2][1] = state[2][3];
        tmp[2][2] = state[2][0];
        tmp[2][3] = state[2][1];

        // Shift row 3 right 3 positions
        tmp[3][0] = state[3][1];
        tmp[3][1] = state[3][2];
        tmp[3][2] = state[3][3];
        tmp[3][3] = state[3][0];

        return tmp;
    }

    /**
     * Helper method used to Substitute key bytes with bytes from the S-Box
     * @param state
     */
    protected int[][] substituteBytes(int[][] state, String operation) {
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                int hexValue = state[i][j];
                state[i][j] = (operation == "enc") ? Utils.sbox[hexValue / 16][hexValue % 16] : Utils.sbox_For_Decryption[hexValue / 16][hexValue % 16];
            }
        }

        return state;
    }

    /**
     * Helper function to perform array deep copies
     * @param state
     */
    protected int[][] deepCopyState(int[][] state) {
        int[][] temp = new int[4][4];
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                temp[i][j] = state[i][j];
            }
        }

        return temp;
    }

    /**
     * Helper file to parse IV into a useful block array
     * @param initializationVector
     */
    public void parseInitializationVector(String initializationVector) {
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                this.initializationVector[j][i] = Integer.parseInt(initializationVector.substring((8 * i) + (2 * j), (8 * i) + (2 * j + 2)), 16);
            }
        }
    }

    /**
     * Converts integer array state to a string
     */
    protected String toString(int[][] state) {
        String output = "";

        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                String k = Integer.toHexString(state[j][i]).toUpperCase();
                if (k.length() == 1) {
                    output += '0' + k;
                } else {
                    output += k;
                }
                output += ' ';
            }
        }

        return output;
    }

    /**
     * Abstract class for encryption
     * To be implemented on an Encryption mode basis
     */
    public abstract String encrypt(String input);

    /**
     * Abstract class for decryption
     * To be implemented on a Decryption mode basis
     */
    public abstract String decrypt(String input);
}