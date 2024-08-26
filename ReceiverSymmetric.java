// These are the imports/packages that are needed for the program to run
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import java.security.MessageDigest;

import java.security.PublicKey;

public class ReceiverSymmetric {
    public static void main(String[] args) throws Exception{
        // 1. Copy and paste the corresponding key files(symmetric.key and XPublic.key) 
        // and the ciphertext file from the sender to the receiver folder

        // 2. Read the information from both key files and generate KXY and KX+
        PublicKey XPublic = readPublicKeyFromFile("XPublic.key"); // Read the public key from the file
        SecretKey symmetricKey = readSymmetricKeyFromFile("symmetric.key"); // Read the symmetric key from the file

        // 3. Display a prompt “Input the name of the message file:” and take a user input from the keyboard.  This 
        // user input provides the name of the file containing the message M.  M can NOT be assumed to be a text message.  The 
        // size of the message M could be much larger than 32KB.

        // This line of code is used to get the user input
        String messageFileName = getUserInput(); // Get the user input

        // 4. Read the ciphertext, C, from the file “message.aescipher” block by block, where each block needs to be a multiple of 16 
        // bytes long.  (Hint: if the length of the last block is less than that multiple of 16 bytes, it needs to be placed in a byte array 
        // whose array size is the length of the last piece before being decrypted.)  Calculate the AES Decryption of C using Kxy 
        // block by block to get RSA-En Kx- (SHA256 (M)) || M, and save the resulting pieces into a file named “message.ds-msg”

        try(InputStream inputStream = new FileInputStream("message.aescipher");// Create an input stream to read the message file
        OutputStream outputStream = new FileOutputStream("message.ds-msg")){ // Create an output stream to write the message file

        Cipher aesCipher = Cipher.getInstance("AES/ECB/PKCS5Padding"); // Create a cipher object
        // Cipher aesCipher = Cipher.getInstance("AES/CBC/NoPadding"); // Create a cipher object
        // Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding"); // Create a cipher object
        
        // byte[] iv = new byte[16]; // Create a byte array to store the initialization vector
        // SecureRandom random = new SecureRandom(); // Create a secure random object
        // random.nextBytes(iv); // Generate the initialization vector
        // IvParameterSpec ivParameterSpec = new IvParameterSpec(iv); // Create an initialization vector parameter spec object
        
        // aesCipher.init(Cipher.DECRYPT_MODE, symmetricKey, ivParameterSpec); // Initialize the cipher object

        aesCipher.init(Cipher.DECRYPT_MODE, symmetricKey); // Initialize the cipher object

        byte[] cipherBlock = new byte[16]; // Create a byte array to store the input bytes with a size of 16 bytes
        int numBytesRead; // Create a variable to store the number of bytes read
        while ((numBytesRead = inputStream.read(cipherBlock)) != -1) { // While there are still bytes to read
            byte[] messageBlock = aesCipher.update(cipherBlock, 0, numBytesRead); // Decrypt the block of the ciphertext
            outputStream.write(messageBlock); // Write the decrypted block of the ciphertext to the file
        }

        System.out.println("AES Decryption of Ciphertext: " + bytesToHexadecimal(cipherBlock)); // Print out the AES decryption of the ciphertext

    } catch (Exception e) { // Catch any exceptions
        e.printStackTrace(); // Print out the stack trace

    
    } // Close the input and output streams

        // 5. If using "RSA/ECB/PKCS1Padding", read the first 128 bytes from the file “message.ds-msg” to get the digital signature 
        // RSA-En Kx- (SHA256 (M)), and copy the message M, i.e., the leftover bytes in the file “message.ds-msg”, to a file whose 
        // name  is  specified  in  Step  3.    (Why  128  bytes?  Why  is  the  leftover  M?)  Calculate  the  RSA  Decryption  of  this  digital 
        // signature using Kx+ to get the digital digest SHA256(M), SAVE this digital digest into a file named “message.dd”, and 
        // DISPLAY it in Hexadecimal bytes.

        BufferedInputStream dsgMsgFile = new BufferedInputStream(new FileInputStream("message.ds-msg")); // Create an input stream to read the message file
        // System.out.println("The length of the file is: " + dsgMsgFile.available()); // Print out the length of the message
        byte[] digitalSignature = new byte[128]; // Create a byte array to store the digital signature
        dsgMsgFile.read(digitalSignature); // Read the digital signature from the file
        // System.out.println("The length of the digital signature is: " + digitalSignature.length); // Print out the length of the digital signature
        dsgMsgFile.close(); // Close the input stream

        // This line of code is used to decrypt the digital signature
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding"); // Create a cipher object
        // Cipher rsaCipher = Cipher.getInstance("RSA/ECB/NoPadding"); // Create a cipher object
        rsaCipher.init(Cipher.DECRYPT_MODE, XPublic); // Initialize the cipher object

        byte[] digitalDigest = rsaCipher.doFinal(digitalSignature); // Decrypt the digital signature

        // This line of code is used to copy the message and write it to a file
        copyMessageandWriteToFile("message.ds-msg", messageFileName); // Copy the message and write it to a file

        FileOutputStream digitalDigestFile = new FileOutputStream("message.dd"); // Create an output stream to write the digital digest file
        digitalDigestFile.write(digitalDigest); // Write the digital digest to the file
        digitalDigestFile.close(); // Close the output stream
        System.out.println("The digital digest/Calculated SHA256(M) is: " + bytesToHexadecimal(digitalDigest)); // Print out the digital digest

        // 6. Read the message M from the file whose name is specified in Step 3 piece by piece, where each piece is recommended to 
        // be a small multiple of 1024 bytes, calculate the SHA256 hash value (digital digest) of the entire message M, DISPLAY it 
        // in Hexadecimal bytes, compare it with the digital digest obtained in Step 5, display whether the digital digest passes the 
        // authentication check.

        // This line of code is used to verify the SHA256 hash of the message
        boolean isVerified = verifySHA256Hash(messageFileName, digitalDigest); // Verify the SHA256 hash of the message

        // This line of code is used to print out the result of the verification
        if (isVerified){ // If the message is verified
            System.out.println("The message is verified"); // Print out the message
        }
        else{ // If the message is not verified
            System.out.println("The message is not verified"); // Print out the message
        }

    }

    // Helper method to read the symmetric key from the file
    public static SecretKey readSymmetricKeyFromFile(String keyFileName) throws IOException{
        byte[] keyBytes = Files.readAllBytes(Paths.get(keyFileName)); // Read the symmetric key from the file
        return new SecretKeySpec(keyBytes, 0, keyBytes.length,"AES"); // Return the symmetric key
    }

    // Helper method to read the public key from the file
    public static PublicKey readPublicKeyFromFile(String keyFileName) throws IOException, ClassNotFoundException{
        try (ObjectInputStream objectInputStream = new ObjectInputStream(new BufferedInputStream(new FileInputStream(keyFileName)))) {
            Object object = objectInputStream.readObject(); // Read the public key from the file
            if (object instanceof PublicKey) { // If the object is an instance of the public key
                return (PublicKey) object; // Return the public key
            }
            else{ // If the object is not an instance of the public key
                throw new IOException("Unexpected type of object"); // Throw an exception
            }
        }
    }

    //Helper method to get the user input of the name of the message file
    public static String getUserInput() throws IOException{
        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(System.in)); // Create a buffered reader to read the user input
        System.out.println("Input the name of the message file: "); // Print out the message
        return bufferedReader.readLine(); // Read the user input

    }

    // Helper method to verify the SHA256 hash of the message
    public static boolean verifySHA256Hash(String fileName, byte[]sha256Hash) throws Exception{
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256"); // Create a message digest object
        try(InputStream inputStream = new FileInputStream(fileName)){ // Create an input stream to read the message file
            byte[] buffer = new byte[1024]; // Create a byte array to store the input bytes
            int numBytesRead; // Create a variable to store the number of bytes read
            while ((numBytesRead = inputStream.read(buffer)) != -1) { // While there are still bytes to read
                messageDigest.update(buffer, 0, numBytesRead); // Update the message digest
            }

        }
        byte[] messageDigestBytes = messageDigest.digest(); // Get the message digest bytes
        System.out.println("The SHA256 hash of the message is: " + bytesToHexadecimal(messageDigestBytes)); // Print out the SHA256 hash of the message
        return MessageDigest.isEqual(sha256Hash, messageDigestBytes); // Return whether the message digest bytes are equal to the SHA256 hash
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

    public static void copyMessageandWriteToFile(String SourceFileName, String TargetFileName) throws IOException{
        // This is a helper method to copy the message and write it to a file
        BufferedInputStream messageFile = new BufferedInputStream(new FileInputStream(SourceFileName)); // Create an input stream to read the message file
        BufferedOutputStream messageFileCopy = new BufferedOutputStream(new FileOutputStream(TargetFileName)); // Create an output stream to write the message file

       
        byte[] buffer = new byte[1024]; // Create a byte array to store the input bytes
        int numBytesRead; // Create a variable to store the number of bytes read
        int messageLength = getMessageLength(messageFile); // Get the length of the message
        System.out.println(messageLength);

        messageFile = new BufferedInputStream(new FileInputStream(SourceFileName)); // Create an input stream to read the message file
        messageFile.skip(128); // Skip the first 128 bytes of the message file
        // Read and copy the actual message part (excluding padding)
        while (messageLength > 0 && (numBytesRead = messageFile.read(buffer, 0, Math.min(buffer.length, messageLength))) != -1) {
            messageFileCopy.write(buffer, 0, numBytesRead);
            messageLength -= numBytesRead;
        }
        messageFile.close(); // Close the input stream
        messageFileCopy.close(); // Close the output stream
    }

    public static int getMessageLength(BufferedInputStream messageFile) throws IOException{
        // This is a helper method to get the length of the message
        int messageLength = 0; // Create a variable to store the length of the message
        byte[] buffer = new byte[1024]; // Create a byte array to store the input bytes
        int numBytesRead; // Create a variable to store the number of bytes read
        
        messageFile.skip(128); // Skip the first 128 bytes of the message file
        
        while ((numBytesRead = messageFile.read(buffer)) != -1) { // While there are still bytes to read
            messageLength += numBytesRead; // Add the number of bytes read to the length of the message

            if(numBytesRead < buffer.length){ // If the number of bytes read is less than the size of the buffer
                for(int i = numBytesRead - 1; i >= 0; i--){ // Loop through the number of bytes read
                    if(buffer[i] == 0x00){ // If the byte is a null byte
                        messageLength--; // Decrement the length of the message
                    }
                    else{ // If the byte is not a null byte
                        break; // Break out of the loop
                    }
                }
            }
        }
        return messageLength; // Return the length of the message
    }

}

