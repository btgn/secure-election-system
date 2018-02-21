
import java.io.*;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.SecureRandom;

public class RSAKeyGenerator
{
    private static final int MIN_KEY_SIZE = 384;
    
    private static final int MAX_KEY_SIZE = 2048;
    
    public static void main(String args[]) throws Exception
    {
        System.out.println("~~~~~~~~~~~~~~~~~~~~~~RSAKeyGenerator~~~~~~~~~~~~~~~~~~~~~~");        
        System.out.println("-- generates a variable bit RSA key pair");        
        System.out.println("--------------Secure Election System----------------------");        
        System.out.println("        B Trilok G Nath, N Ravi Kanth, P Mounika");        
        System.out.println();
        System.out.println(" Enter q at the beginning of a line and hit enter to quit");
        System.out.println("===========================================================");
                
        if (args.length != 2) 
        {
            System.out.println("\nUsage:\nRSAKeyGenerator <KEY_BIT_SIZE> <KEY_FILE_PREFIX>");
            System.exit(1);
        }
        
        int keySize = 0;
        try 
        {
            keySize = Integer.parseInt(args[0]);
            if(keySize < MIN_KEY_SIZE || keySize > MAX_KEY_SIZE)
                throw new NumberFormatException();
        }
        catch(NumberFormatException ex) 
        {
            System.out.println("\nUsage:\nRSAKeyGenerator <KEY_BIT_SIZE> <KEY_FILE_PREFIX>");
            System.out.println("~~~ " + MIN_KEY_SIZE + " <= KEY_BIT_SIZE <= " + MAX_KEY_SIZE);
            System.exit(1);
        }
            
        java.security.Provider prov = new cryptix.jce.provider.CryptixCrypto();
        java.security.Security.addProvider( prov );
    
        System.out.println("~~~ Initializing key generator...");        
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA","CryptixCrypto");        
        keyGen.initialize(keySize, new SecureRandom());
        
        System.out.println("~~~ Generating " + keySize + " bit RSA key pair...");        
        KeyPair keyPair = keyGen.genKeyPair();
        
        RSAPrivateKey privateKey = (RSAPrivateKey)keyPair.getPrivate();
        RSAPublicKey publicKey = (RSAPublicKey)keyPair.getPublic();
            
        String privateFileName = args[1] + ".private"; 
        System.out.println("~~~ Outputting private key to file: " + privateFileName + "...");
        ObjectOutputStream privateStream = new ObjectOutputStream (new FileOutputStream(privateFileName, false));
        privateStream.writeObject(privateKey);
        privateStream.close();
        
        String publicFileName = args[1] + ".public"; 
        System.out.println("~~~ Outputting public key to file: " + publicFileName + "...");
        ObjectOutputStream publicStream = new ObjectOutputStream (new FileOutputStream(publicFileName, false));
        publicStream.writeObject(publicKey);
        publicStream.close();

        System.out.println("~~~ Done...");        
    }
}
