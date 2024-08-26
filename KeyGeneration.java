// These are the libraries that are used in this program

import java.io.*;

import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.KeyFactory;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.RSAPrivateKeySpec;

import java.math.BigInteger;

public class KeyGeneration {
    public static void main(String[] args) throws Exception{

        SecureRandom random = new SecureRandom(); // Generate a random number

        // The purpose of these lines are to generate key pairs for x and y
        KeyPairGenerator xKeyPairGenerator = KeyPairGenerator.getInstance("RSA"); 
        xKeyPairGenerator.initialize(1024, random); // The key size is 1024 bits
        KeyPair xKeyPair = xKeyPairGenerator.genKeyPair(); // Generate the key pair

        // The purpose of these lines are to generate key pairs for x and y
        KeyPairGenerator yKeyPairGenerator = KeyPairGenerator.getInstance("RSA");
        yKeyPairGenerator.initialize(1024, random);
        KeyPair yKeyPair = yKeyPairGenerator.genKeyPair();

        // 1. Create a pair of RSA public and pr ivate keys for X, Kx+ and Kx–;
        Key xPublicPair = xKeyPair.getPublic(); // Get the public key of x
        Key yPublicPair = yKeyPair.getPublic(); // Get the public key of y

        //2. Create a pair of RSA public and private keys for Y, Ky+ and Ky–;
        Key xPrivatePair = xKeyPair.getPrivate(); // Get the private key of x
        Key yPrivatePair = yKeyPair.getPrivate(); // Get the private key of y

        // 3. Get the modulus and exponent of each RSA public or private key and save them into files named “XPublic.key”, “XPrivate.key”, 
        //“YPublic.key”, and “YPrivate.key”, respectively; 

        KeyFactory xKeyFactory = KeyFactory.getInstance("RSA"); // Get the key factory of x
        KeyFactory yKeyFactory = KeyFactory.getInstance("RSA"); // Get the key factory of y

        //These lines of code are getting the parameters of modulus and exponent
        RSAPublicKeySpec xPublicKeySpec = xKeyFactory.getKeySpec(xPublicPair, RSAPublicKeySpec.class); // Get the public key spec of x
        RSAPublicKeySpec yPublicKeySpec = yKeyFactory.getKeySpec(yPublicPair, RSAPublicKeySpec.class); // Get the public key spec of y
        RSAPrivateKeySpec xPrivateKeySpec = xKeyFactory.getKeySpec(xPrivatePair, RSAPrivateKeySpec.class); // Get the private key spec of x
        RSAPrivateKeySpec yPrivateKeySpec = yKeyFactory.getKeySpec(yPrivatePair, RSAPrivateKeySpec.class); // Get the private key spec of y

        // These lines of code are saving the modulus and exponent of each RSA public or private key into files
        savePublicKeyToFile("XPublic.key", xPublicKeySpec.getModulus(), xPublicKeySpec.getPublicExponent()); // Save the modulus and exponent of x public key into a file
        saveToFile("XPrivate.key", xPrivateKeySpec.getModulus(), xPrivateKeySpec.getPrivateExponent()); // Save the modulus and exponent of x private key into a file
        savePublicKeyToFile("YPublic.key", yPublicKeySpec.getModulus(), yPublicKeySpec.getPublicExponent()); // Save the modulus and exponent of y public key into a file
        saveToFile("YPrivate.key", yPrivateKeySpec.getModulus(), yPrivateKeySpec.getPrivateExponent()); // Save the modulus and exponent of y private key into a file

        // 4. Take  a  16-character  user  input  from  the  keyboard  and  save  this  16-character  string  to  a  file  named  “symmetric.key”.    This 
        // string’s 128-bit UTF-8 encoding will be used as the 128-bit AES symmetric key, Kxy, in your application.

        // This line of code is used to get the user input
        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(System.in)); // Create a buffered reader to read the user input
        System.out.println("Enter a 16-character string: "); // Print out the message
        String input = bufferedReader.readLine(); // Read the user input

        if (input.length() != 16) { // If the user input is not 16 characters
            System.out.println("The input is not 16 characters"); // Print out the message
            System.exit(0); // Exit the program
        }

        byte[] inputBytes = input.getBytes("UTF8"); // Convert the user input to bytes
        FileOutputStream fileOutputStream = new FileOutputStream("symmetric.key"); // Create a file output stream to write to the file with the given name
        fileOutputStream.write(inputBytes); // Write the user input to the file
        fileOutputStream.close(); // Close the file output stream

    }

    // This helper method is used to save the modulus and exponent of each RSA public or private key into files
    public static void saveToFile(String fileName, BigInteger mod, BigInteger exp) throws IOException {
        try(ObjectOutputStream objectOutputStream = new ObjectOutputStream(new BufferedOutputStream(new FileOutputStream(fileName)))) { // Create a file output stream to write to the file with the given name
            RSAPrivateKey key = (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(new RSAPrivateKeySpec(mod, exp)); // Generate the private key
            objectOutputStream.writeObject(key); // Write the key to the file
            System.out.println(fileName + " is generated");
        } catch (Exception e) { // Catch the exception
            throw new IOException("Unexpected error", e); // Throw an exception
        }
    }

    // This helper method is to save the public key into a file
    public static void savePublicKeyToFile(String fileName, BigInteger mod, BigInteger exp) throws IOException {
        try(ObjectOutputStream objectOutputStream = new ObjectOutputStream(new BufferedOutputStream(new FileOutputStream(fileName)))) { // Create a file output stream to write to the file with the given name
            RSAPublicKey key = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(mod, exp)); // Generate the private key
            objectOutputStream.writeObject(key); // Write the key to the file
            System.out.println(fileName + " is generated");
        } catch (Exception e) { // Catch the exception
            throw new IOException("Unexpected error", e); // Throw an exception
        }
    }

    }



    

