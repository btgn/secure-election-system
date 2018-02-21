
import java.net.*;

import java.io.*;
import javax.crypto.*;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.Signature;
import java.util.Hashtable;
import java.util.Random;
import java.math.BigInteger;
import javax.crypto.spec.SecretKeySpec;

public class CLAService
{
    public static final int VOTER_TO_CLA_PORT = 7676;
    
    public static final int CLA_TO_CTF_PORT = 7677;

    private String m_CTFServerName = null;

    private RSAPublicKey m_publicKey = null;

    private RSAPrivateKey m_privateKey = null;

    private RSAPublicKey m_publicCAKey = null;
    
    private byte[] m_publicKeyCert;

    private Hashtable<String, BigInteger> m_voterList = new Hashtable<String, BigInteger>();
    
    private boolean m_listening = false;

    CLAService(String CTFServer)
    {
        m_CTFServerName = CTFServer;
    }

    public static void main(String args[]) throws Exception
    {
        System.out.println("~~~~~~~~~~~~~~~~~~~~~~CLAService~~~~~~~~~~~~~~~~~~~~~~");        
        System.out.println("--------------Secure Election System----------------------");        
        System.out.println("        B Trilok G Nath, N Ravi Kanth, P Mounika");        
        System.out.println();
        System.out.println(" Enter q at the beginning of a line and hit enter to quit");
        System.out.println("===========================================================");
                    
        if (args.length != 1)                     
        {
            System.out.println("Usage:\nCLAService <CTFServerName>");        
            System.exit(1);
        }                            
                    
        CLAService claService = new CLAService(args[0]);
        if(!claService.start())
        {
            System.exit(1);
        }
    }

    @SuppressWarnings("resource")
	public boolean start() 
    {
        try 
        {
            java.security.Provider prov = new cryptix.jce.provider.CryptixCrypto();
            java.security.Security.addProvider( prov );
        
            System.out.println("~~~ Reading CLA public key from file: CLA.public...");        
            ObjectInputStream stream = new ObjectInputStream (new FileInputStream("CLA.public"));
            m_publicKey = (RSAPublicKey)stream.readObject();
            stream.close();

            System.out.println("~~~ Reading CLA private key from file: CLA.private...");        
            stream = new ObjectInputStream (new FileInputStream("CLA.private"));
            m_privateKey = (RSAPrivateKey)stream.readObject();
            stream.close();

            System.out.println("~~~ Reading certificate from file: CLA.cert...");        
            DataInputStream certStream = new DataInputStream (new FileInputStream("CLA.cert"));
            int certLength = certStream.readInt();
            m_publicKeyCert = new byte[certLength];
            certStream.read(m_publicKeyCert, 0, m_publicKeyCert.length);
            certStream.close();

            stream = new ObjectInputStream (new FileInputStream("CA.public"));
            m_publicCAKey = (RSAPublicKey)stream.readObject();
            stream.close();

            System.out.println("~~~ Reading list of voters from: CLA.voters...");        
            BufferedReader voterStream = new BufferedReader (new FileReader("CLA.voters"));
            String voter;
            while ((voter = voterStream.readLine()) != null) 
            {
                voter = voter.trim();
                if (voter.length() > 0) 
                {
                    System.out.println("   ~~~ Adding voter: " + voter);        
                    m_voterList.put(voter, BigInteger.ZERO);
                }
            }
            
            System.out.println("~~~ Starting CLA service on port " + VOTER_TO_CLA_PORT + "...");        
            ServerSocket serverSocket = new ServerSocket(VOTER_TO_CLA_PORT);
            m_listening = true;

            System.out.println("~~~ Waiting for voter registrations...");        
            new ConsoleThread().start();
            while (m_listening)
            {
                new CLAServerThread(serverSocket.accept()).start();
            }
            serverSocket.close();
        }
        catch(Exception ex) 
        {
            System.out.println("** Error starting CLA: " + ex);
            return false;
        }
        return true;
    }

    class CLAServerThread extends Thread
    {
        private static final int KEY_SIZE = 448;

        private Cipher m_pkCipher = null;

        private Cipher m_cipher = null;

        private Socket m_socket = null;

        public CLAServerThread(Socket socket)
        {
            m_socket = socket;
        }
        
        @SuppressWarnings("unused")
		public void run()
        {
            try 
            {
                System.out.println("\n### Received data from Voter");
                m_pkCipher = Cipher.getInstance( "RSA/ECB/PKCS#1", "CryptixCrypto" );
                m_cipher = Cipher.getInstance( "Blowfish/ECB/PKCS#5", "CryptixCrypto" );

                ObjectOutputStream output = new ObjectOutputStream(m_socket.getOutputStream());
                ObjectInputStream input = new ObjectInputStream(m_socket.getInputStream());
                
                output.writeObject(m_publicKey);
                output.writeObject(m_publicKeyCert);
                
                System.out.println("~~~ Using private RSA key to decrypt key from Voter");
                m_pkCipher.init(Cipher.DECRYPT_MODE, m_privateKey);
                byte[] decryptedKeyBytes = m_pkCipher.doFinal((byte[])input.readObject());

                ByteArrayInputStream keyBytes = new ByteArrayInputStream(decryptedKeyBytes);
                DataInputStream keyStream = new DataInputStream(keyBytes);
                
                String algorithm = keyStream.readUTF();
                int length = keyStream.readInt();
                byte[] encodedKey = new byte[length];
                keyStream.readFully(encodedKey);
                SecretKey symmetricKey = new SecretKeySpec(encodedKey, algorithm);
                
                keyStream.close();
                keyBytes.close();                
                
                System.out.println("~~~ Using key to decrypt data from Voter");
                byte[] encryptedLogin = (byte[])input.readObject();
                m_cipher.init(Cipher.DECRYPT_MODE, symmetricKey);
                byte[] decryptedLogin = m_cipher.doFinal(encryptedLogin);
                
                ObjectInputStream loginStream = new ObjectInputStream(new ByteArrayInputStream(decryptedLogin));
                String voter = (String)loginStream.readObject();
                RSAPublicKey voterKey = (RSAPublicKey)loginStream.readObject();
                
                loginStream.close();
            
                ByteArrayOutputStream responseBytes = new ByteArrayOutputStream();
                ObjectOutputStream responseStream = new ObjectOutputStream(responseBytes);
                
                BigInteger voteValidation = m_voterList.get(voter);
                if (voteValidation == null) 
                {
                    System.out.println("~~~ Login of: " + voter + " rejected");
                    responseStream.writeObject(new String("ERROR"));
                    responseStream.writeObject(new String("Login rejected"));
                }
                else if (voteValidation.compareTo(BigInteger.ZERO) != 0) 
                {
                    System.out.println("~~~ Login of " + voter + " accepted, returning previous ValidationId " + voteValidation);
                    responseStream.writeObject(new String("REPEAT"));
                    responseStream.writeObject(voteValidation);                    
                }
                else 
                {
                    voteValidation = new BigInteger(64, new Random());
                    System.out.println("~~~ Login of " + voter + " accepted, creating new ValidationId " +voteValidation);
                    
                    if (doCTFRegister(voteValidation))                                 
                    {                                
                        m_voterList.put(voter, voteValidation);
                        responseStream.writeObject(new String("NEW"));
                        responseStream.writeObject(voteValidation);                    
                    }
                    else 
                    {
                        responseStream.writeObject(new String("ERROR"));
                        responseStream.writeObject(new String("CTF not responding!"));
                    }
                }
                
                responseStream.writeObject(new Long(System.currentTimeMillis()));
                
                System.out.println("~~~ Using key to encrypt data for Voter");
                m_cipher.init(Cipher.ENCRYPT_MODE, symmetricKey);
                output.writeObject(m_cipher.doFinal(responseBytes.toByteArray()));
                
                System.out.println("~~~ Generating and sending an RSA signature of the data to the Voter");
                Signature sig = Signature.getInstance("SHA1withRSA");
                sig.initSign(m_privateKey);
                sig.update(responseBytes.toByteArray());
                output.writeObject(sig.sign());
                
                System.out.println("### Done sending response to Voter");
                responseStream.close();
                output.close();
                m_socket.close();
            }
            catch(Exception ex)
            {
                System.out.println("** Error communicating with Voter: " + ex);
                try
                {
                    m_socket.close();
                }
                catch(java.io.IOException ioe)
                {
                    ioe.printStackTrace();
                }    
            }
        }
                
        private boolean doCTFRegister(BigInteger voteValidation)
        {
            boolean success = false;
            try 
            {
                System.out.println("\n### Sending data to CTF");
                Socket socket = new Socket(m_CTFServerName, CLA_TO_CTF_PORT);
                
                ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());
                ObjectInputStream input = new ObjectInputStream(socket.getInputStream());

                System.out.println( "~~~ Generating key with bitsize " + KEY_SIZE + " for transmission to CTF" );
                KeyGenerator kg = KeyGenerator.getInstance("Blowfish","CryptixCrypto");
                kg.init(KEY_SIZE, new SecureRandom());
                SecretKey symmetricKey = kg.generateKey();
            
                RSAPublicKey ctfKey = (RSAPublicKey)input.readObject();
                byte[] ctfCert = (byte[])input.readObject();
                
                ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
                ObjectOutputStream contentStream = new ObjectOutputStream(byteStream);
                contentStream.writeObject(ctfKey);
                contentStream.writeObject(new String("CTF"));
                    
                Signature sig = Signature.getInstance("SHA1withRSA");
                sig.initVerify(m_publicCAKey);
                sig.update(byteStream.toByteArray());                
                if(!sig.verify(ctfCert))
                {
                    System.out.println("** CTF certification failed");
                    socket.close();
                    return false;
                }
                else
                {
                    System.out.println("~~~ CTF certificate verified");
                }    
                
                contentStream.close();
                byteStream.close();
                
                ByteArrayOutputStream keyBytes = new ByteArrayOutputStream();
                DataOutputStream keyStream = new DataOutputStream(keyBytes);
                byte [] encodedKey = symmetricKey.getEncoded();
                keyStream.writeUTF(symmetricKey.getAlgorithm());
                keyStream.writeInt(encodedKey.length);
                keyStream.write(encodedKey, 0, encodedKey.length);
                
                System.out.println("~~~ Using CTF's public RSA key to encrypt key");
                m_pkCipher.init(Cipher.ENCRYPT_MODE, ctfKey);
                output.writeObject(m_pkCipher.doFinal(keyBytes.toByteArray()));

                keyStream.close();
                keyBytes.close();

                ByteArrayOutputStream requestBytes = new ByteArrayOutputStream();
                ObjectOutputStream requestStream = new ObjectOutputStream(requestBytes);
                
                System.out.println("~~~ Contacting CTF to register new Voter " + voteValidation);
                requestStream.writeObject(m_publicKey);
                requestStream.writeObject(new String("ADD"));
                
                requestStream.writeObject(m_publicKeyCert);
                
                requestStream.writeObject(voteValidation);
                
                System.out.println("~~~ Using key to encrypt data for CTF");
                m_cipher.init(Cipher.ENCRYPT_MODE, symmetricKey);
                byte[] encryptedRequest = m_cipher.doFinal(requestBytes.toByteArray());
                output.writeObject(encryptedRequest);

                System.out.println("~~~ Generating and sending an RSA signature of data for CTF");
                sig.initSign(m_privateKey);
                sig.update(requestBytes.toByteArray());
                output.writeObject(sig.sign());
                        
                requestStream.close();
                
                System.out.println("~~~ Using key to decrypt data from CTF");
                m_cipher.init(Cipher.DECRYPT_MODE, symmetricKey);
                byte[] encryptedResponse = (byte[])input.readObject();
                byte[] decryptedResponse = m_cipher.doFinal(encryptedResponse);

                System.out.println("~~~ Verifying CTF signature of data from CTF");
                sig.initVerify(ctfKey);
                sig.update(decryptedResponse);                
                if(!sig.verify((byte[])input.readObject()))
                {
                    System.out.println("** CTF signature failed\n");
                    socket.close();
                    return false;
                }
                else
                {
                    System.out.println("~~~ CTF signature verified");
                }

                ObjectInputStream responseStream = new ObjectInputStream(new ByteArrayInputStream(decryptedResponse));
                String responseType = (String)responseStream.readObject();
                if (responseType.equals("OK")) 
                {
                    success = true;
                }
                else if(responseType.equals("ERROR")) 
                {
                    System.out.println("** Error from CTF: " + (String)responseStream.readObject());
                }
                else 
                {
                    System.out.println("** unknown response from CTF");
                }
                System.out.println("### Done receiving response from CTF");
                responseStream.close();
                socket.close();
            }
            catch(Exception ex)
            {
                if (ex.getClass().isInstance(new java.net.ConnectException())
                    || ex.getClass().isInstance(new java.io.EOFException()))
                {
                    System.out.println("** Error communicating with CTF: " + ex.getMessage());
                }
                else
                {
                    ex.printStackTrace();
                }
                success = false;
            }
            System.out.println();
            return success;
        }
    }

    class ConsoleThread extends Thread
    {
        public void run()
        {
            try
            {
                BufferedReader inputStream = new BufferedReader(new InputStreamReader(System.in));
                boolean exit = false;
                while (exit == false)
                {
                    String theKeys = inputStream.readLine();
                    if (theKeys.length() > 0)
                    {
                        if (theKeys.charAt(0) == 'q')
                        {
                            exit = true;
                        }
                    }    
                }
                System.out.println("CLAService Closed by User...");
                System.exit(0);    
            }
            catch (Exception ex)
            {
                ex.printStackTrace();
            }    
        }
    }
}
