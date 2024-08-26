// These are the imports that are used for this sender program
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.PrivateKey;



public class SenderSymmetric {
    public static void main(String[] args) throws Exception{
        // 1. Copy and paste the corresponding key file (symmetric.key) from the KeyGen directory into the Sender directory;
        // 2. Read the 16-character string from the file “symmetric.key”;
        
        // These lines of code are used to read the symmetric key from the file and
        PrivateKey kxMinusPrivateKey = readPrivateKeyFromFile("XPrivate.key");
        SecretKey symmetricKey = readSymmetricKeyFromFile("symmetric.key");

        // 3 Display a prompt “Input the name of the message file:” and take a user input from the keyboard.  This 
        // user input provides the name of the file containing the message M.  M can NOT be assumed to be a text message.  The 
        // size of the message M could be much larger than 32KB.

        // This line of code is used to get the user input
        String messageFileName = getUserInput(); // Get the user input

        // 4. Read the message M from the file named by the user input and compute the hash value of M using SHA-256.
        int numBytesRead; // This variable is used to store the number of bytes read
        BufferedInputStream messageFileStream = new BufferedInputStream(new FileInputStream(messageFileName)); // Create a buffered input stream object to read the message file
        System.out.println("The length of the message is: " + messageFileStream.available() + "bytes"); // Print out the size of the message
        MessageDigest md = MessageDigest.getInstance("SHA-256"); // Create a message digest object
        try (DigestInputStream in = new DigestInputStream(messageFileStream, md)) { // Create a digest input stream object
            byte[] plaintext = new byte[32 * 1024]; // This variable is used to store the plaintext with a size of 32KB
            while(true){ // Loop until the end of the file is reached
                numBytesRead = in.read(plaintext, 0, plaintext.length); // Read the message file
                if(numBytesRead <= 0){ // If the end of the file is reached
                    break; // Break out of the loop
                }
            }
        } // The 'in' stream is automatically closed here
        // System.out.println("The size of the message is: " + numBytesRead + " bytes"); // Print out the size of the message

        // Optionally: After calculating SHA256(M) but before saving it to the file named “message.dd” (the sender’s program), 
        // display a prompt “Do you want to invert the 1st byte in SHA256(M)? (Y or N)”, 
        // If the user input is ‘Y’, modify the first byte in your byte array holding SHA256(M) by replacing it with its bitwise 
        // inverted value (hint: the ~ operator in Java does it), complete the rest of Step 4 by SAVING & DISPLAYING the 
        // modified  SHA256(M),  instead  of  the  original  SHA256(M),  and  continue  to  Step  5  (also  use  the  modified 
        // SHA256(M), instead of the original SHA256(M), in Steps 5 & 6). 
        // Otherwise (if the user input is ‘N’), make NO change to the byte array holding SHA256(M), complete the rest of 
        // Step 4 (SAVE and DISPLAY), and continue to Step 5.

        

        // This line of code is used to get the user input for the invert byte prompt
        Boolean invertByte = invertBytePrompt(); // Get the user input for the invert byte prompt
        byte[] SHA256hash = md.digest(); // Compute the hash value of M using SHA-256
        String SHA256hashStringOriginal = bytesToHexadecimal(SHA256hash); // Convert the hash value to a hexadecimal string
        System.out.println("Original SHA256(M): " + SHA256hashStringOriginal); // Print out the hash value
        if (invertByte){ // If the user input is Y
            SHA256hash[0] = (byte)~SHA256hash[0]; // Invert the first byte of the hash value
        }

        String SHA256hashString = bytesToHexadecimal(SHA256hash); // Convert the hash value to a hexadecimal string
        saveByteArrayToFile(SHA256hash, "message.dd"); // Save the hexadecimal string to the file
        System.out.println("The size of the hash value is: " + SHA256hash.length + " bytes"); // Print out the size of the hash value
        System.out.println("SHA256(M): " + SHA256hashString); // Print out the hash value

        // Calculate the RSA Encryption of SHA256(M) using Kx – (Question: how many bytes is the cyphertext?), SAVE this RSA 
        // cyphertext  (the  digital  signature  of  M),  into  a  file  named  “message.ds-msg”,  and  DISPLAY  it  in  Hexadecimal  bytes.  
        // APPEND the message M read from the file specified in Step 3 to the file “message.ds-msg” piece by piece.

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding"); // Create a cipher object
        // Cipher cipher = Cipher.getInstance("RSA/ECB/NoPadding"); // Create a cipher object
        cipher.init(Cipher.ENCRYPT_MODE, kxMinusPrivateKey); // Initialize the cipher object

        byte[] cipherText = cipher.doFinal(SHA256hash); // Encrypt the hash value

        System.out.println("RSA Encryption of SHA256(M): " + bytesToHexadecimal(cipherText)); // Print out the RSA encryption of the hash value
        System.out.println("The size of the cyphertext is: " + cipherText.length + " bytes"); // Print out the size of the cyphertext

        FileOutputStream fileOutputStream = new FileOutputStream("message.ds-msg"); // Create a file output stream object to write to the file with the given name
        fileOutputStream.write(cipherText); // Write the RSA encryption of the hash value to the file

        // This line of code is used to append the message to the file
        int bytesRead; // This variable is used to store the number of bytes read
        BufferedInputStream messageFileStream2 = new BufferedInputStream(new FileInputStream(messageFileName)); // Create a buffered input stream object to read the message file
        byte[] messageFileBlock = new byte[1024]; // This variable is used to store the message file block with a size of 32KB
        while((bytesRead = messageFileStream2.read(messageFileBlock)) != -1){ // Loop until the end of the file is reached
            fileOutputStream.write(messageFileBlock, 0, bytesRead); // Write the message file block to the file
        }
        fileOutputStream.close(); // Close the file output stream
        messageFileStream2.close(); // Close the buffered input stream

        // Calculate the AES Encryption of (RSA-En Kx– (SHA256 (M)) || M) using Kxy by reading the file “message.ds-msg” piece 
        // by piece, where each piece is recommended to be a multiple of 16 bytes long.  (Hint: if the length of the last piece is less 
        // than that multiple of 16 bytes, it needs to be placed in a byte array whose array size is the length of the last piece before 
        // being encrypted.)  SAVE the resulting blocks of AES ciphertext into a file named “message.aescipher”

        try(InputStream inputStream = new FileInputStream("message.ds-msg"); // Create an input stream object to read the file with the given name
        OutputStream outputStream = new FileOutputStream("message.aescipher")){ // Create an output stream object to write to the file with the given name

        cipher = Cipher.getInstance("AES/ECB/PKCS5Padding"); // Create a cipher object
        // cipher = Cipher.getInstance("AES/CBC/NoPadding"); // Create a cipher object
        // cipher = Cipher.getInstance("AES/CBC/PKCS5Padding"); // Create a cipher object

        // byte[] ivBytes = new byte[16]; // This variable is used to store the initialization vector
        // SecureRandom secureRandom = new SecureRandom(); // Create a secure random object
        // secureRandom.nextBytes(ivBytes); // Generate the initialization vector

        // IvParameterSpec ivParameterSpec = new IvParameterSpec(ivBytes); // Create an initialization vector parameter spec object

        // cipher.init(Cipher.ENCRYPT_MODE, symmetricKey, ivParameterSpec); // Initialize the cipher object

        cipher.init(Cipher.ENCRYPT_MODE, symmetricKey); // Initialize the cipher object


        byte[] cipherTextBlock = new byte[16]; // This variable is used to store the cipher text block with a multiple of 16 bytes
        int numBytesRead2; // This variable is used to store the number of bytes read

        while((numBytesRead2 = inputStream.read(cipherTextBlock)) != -1){ // Loop until the end of the file is reached
            if(numBytesRead2 % 16 != 0){ // If the number of bytes read is not a multiple of 16
                System.out.println("The number of bytes read is not a multiple of 16"); // Print out the message
                System.out.println("The number of bytes read is: " + numBytesRead2); // Print out the number of bytes read
                byte[] temp = new byte[16]; // This variable is used to store the temporary byte array
                for(int i = 0; i < numBytesRead2; i++){ // Loop through the number of bytes read
                    temp[i] = cipherTextBlock[i]; // Copy the bytes to the temporary byte array
                }
                cipherTextBlock = temp; // Copy the temporary byte array to the cipher text block
                System.out.println("The number of bytes in the cipher text block is: " + cipherTextBlock.length); // Print out the number of bytes in the cipher text block
                byte[] cipherTextBlockEncrypted = cipher.update(cipherTextBlock); // Encrypt the cipher text block
                outputStream.write(cipherTextBlockEncrypted); // Write the cipher text block to the file
                System.out.println(bytesToHexadecimal(cipherTextBlock)); // Print out the cipher text block as a hexadecimal string
            }
            byte[] cipherTextBlockEncrypted = cipher.update(cipherTextBlock); // Encrypt the cipher text block
            outputStream.write(cipherTextBlockEncrypted); // Write the cipher text block to the file
        }

        // byte[]finalBlock = cipher.doFinal(); // Encrypt the final block
        // outputStream.write(finalBlock); // Write the final block to the file


    } // The 'inputStream' and 'outputStream' streams are automatically closed here


    }

    //Helper method to get the user input of the name of the message file
    public static String getUserInput() throws IOException{
        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(System.in)); // Create a buffered reader to read the user input
        System.out.println("Input the name of the message file: "); // Print out the message
        return bufferedReader.readLine(); // Read the user input

    }

    // Helper method to read the symmetric key from the file
    public static SecretKey readSymmetricKeyFromFile(String keyFileName) throws IOException{
        byte[] keyBytes = Files.readAllBytes(Paths.get(keyFileName)); // Read the symmetric key from the file
        return new SecretKeySpec(keyBytes, 0, keyBytes.length,"AES"); // Return the symmetric key
    }

    // Helper method to read the private key from the file
    public static PrivateKey readPrivateKeyFromFile(String keyFileName) throws IOException, ClassNotFoundException{
        try (ObjectInputStream objectInputStream = new ObjectInputStream(new BufferedInputStream(new FileInputStream(keyFileName)))) {
            Object object = objectInputStream.readObject(); // Read the private key from the file
            if (object instanceof PrivateKey) { // If the object is an instance of the private key
                return (PrivateKey) object; // Return the private key
            }
            else{ // If the object is not an instance of the private key
                throw new IOException("Unexpected type of object"); // Throw an exception
            }
            // return (PrivateKey) objectInputStream.readObject(); // Return the private key
        }
    }

    // Helper method to display the prompt to the user to invert the first byte of the hash value
    public static Boolean invertBytePrompt() throws IOException{
        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(System.in)); // Create a buffered reader to read the user input
        System.out.println("Do you want to invert the 1st byte in SHA256(M)? (Y or N)"); // Print out the message
        String userInput = bufferedReader.readLine(); // Read the user input
        if(userInput.equals("Y")){ // If the user input is Y
            return true; // Return true
        }
        else{ // If the user input is N
            return false; // Return false
        }
    }

    // Helper method to convert the byte array into a hexadeciaml string
    public static String bytesToHexadecimal(byte[] bytes) throws IOException{
        StringBuilder hexaString = new StringBuilder(); // Create a string builder object
        // for(byte b : bytes){ // Loop through the byte array
        //     hexaString.append(String.format("%02X", b)); // Append the hexadecimal value of the byte to the string builder
        // }

        for(int i = 0; i < bytes.length; i++){ // Loop through the byte array
            hexaString.append(String.format("%02X", bytes[i])); // Append the hexadecimal value of the byte to the string builder
            if(i % 16 == 15){ // If the index is a multiple of 16
                hexaString.append("\n"); // Append a new line
            }
            if(i < bytes.length - 1){ // If the index is not the last index
                hexaString.append(" "); // Append a space
            }
        }

        return hexaString.toString(); // Return the string builder as a string

    }

    // Helper method to save the hexadecimal string to the file
    public static void saveByteArrayToFile(byte[] byteArray, String fileName) throws IOException{
        BufferedInputStream bufferedInputStream = new BufferedInputStream(new ByteArrayInputStream(byteArray)); // Create a buffered input stream object to read the byte array
        BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(new FileOutputStream(fileName)); // Create a buffered output stream object to write to the file with the given name
        int numBytesRead; // This variable is used to store the number of bytes read
        byte[] block = new byte[1024]; // This variable is used to store the block with a size of 1024 bytes
        while((numBytesRead = bufferedInputStream.read(block)) != -1){ // Loop until the end of the file is reached
            bufferedOutputStream.write(block, 0, numBytesRead); // Write the block to the file
        }
        bufferedOutputStream.close(); // Close the buffered output stream
    }

    
}


