
import java.net.*;

import java.io.*;
import javax.crypto.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.Signature;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Vector;
import java.awt.event.*; 

public class VoterService
{
    public static final int VOTER_TO_CLA_PORT = 7676;
    
    public static final int VOTER_TO_CTF_PORT = 7677;

    private static final int KEY_SIZE = 448;

    private static final String welcomeString = new String("- Welcome to Secure Election System \n\n- Please login to enable voting facilities\n\n");
        
    private UserInterfaceWindow window;

    private String m_CLAServerName = null;
    
    private String m_CTFServerName = null;
    
    private Cipher m_pkCipher = null;

    private Cipher m_cipher = null;
    
    private RSAPublicKey m_publicKey = null;

    private RSAPrivateKey m_privateKey = null;

    private RSAPublicKey m_publicCAKey = null;

    private Vector<?> m_candidateList = null;

    private String m_voterId = null;
    
    private BigInteger m_validationId = null;
        
    private boolean m_listening = false;
    
    public VoterService( String CLAServer, String CTFServer )
    { 
        m_CLAServerName = CLAServer;
        m_CTFServerName = CTFServer;
        
        window = new UserInterfaceWindow();
    
        window.addWindowListener( 
            new WindowAdapter() { 
                public void windowClosing(WindowEvent e)
                { 
                    System.out.println("VoterService Closed by User...");
                    System.exit(0);
                } 
        }); 

        window.getSubmitVoterIdButton().addActionListener( new ActionListener() { 
            public void actionPerformed(ActionEvent event){ submitVoterId(); } } ); 

        window.getSubmitCandidateIdButton().addActionListener( new ActionListener() { 
            public void actionPerformed(ActionEvent event){ submitCandidateId(); } } ); 

        window.getVerifyVoteButton().addActionListener( new ActionListener() { 
            public void actionPerformed(ActionEvent event){ verifyVote(); } } ); 

        window.getVoteResultsButton().addActionListener( new ActionListener() { 
            public void actionPerformed(ActionEvent event){ voteResults(); } } ); 
    
        window.getLogoutButton().addActionListener( new ActionListener() { 
            public void actionPerformed(ActionEvent event){ logout(); } } );
    
        window.getResultsArea().append(welcomeString);
    }    

    public static void main(String args[]) throws Exception
    {
        System.out.println("~~~~~~~~~~~~~~~~~~~~~~VoterService~~~~~~~~~~~~~~~~~~~~~~");        
        System.out.println("--------------Secure Election System----------------------");        
        System.out.println("        B Trilok G Nath, N Ravi Kanth, P Mounika");        
        System.out.println();
        System.out.println(" Enter q at the beginning of a line and hit enter to quit");
        System.out.println("===========================================================");
                    
        if (args.length != 2)                     
        {
            System.out.println("Usage:\n VoterService <CLAServerName> <CTFServerName>");        
            System.exit(1);
        }                            
                    
        VoterService voterService = new VoterService(args[0], args[1]);
        if (!voterService.start())
        {
            System.exit(1);
        }
    }

    public boolean start() 
    {
        try 
        {
            java.security.Provider prov = new cryptix.jce.provider.CryptixCrypto();
            java.security.Security.addProvider( prov );
            m_pkCipher = Cipher.getInstance( "RSA/ECB/PKCS#1", "CryptixCrypto" );
            m_cipher = Cipher.getInstance( "Blowfish/ECB/PKCS#5", "CryptixCrypto" );
            
            System.out.println("~~~ Reading Voter public key from file: Voter.public...");        
            ObjectInputStream stream = new ObjectInputStream (new FileInputStream("Voter.public"));
            m_publicKey = (RSAPublicKey)stream.readObject();
            stream.close();

            System.out.println("~~~ Reading Voter private key from file: Voter.private...");        
            stream = new ObjectInputStream (new FileInputStream("Voter.private"));
            setM_privateKey((RSAPrivateKey)stream.readObject());
            stream.close();           

            stream = new ObjectInputStream (new FileInputStream("CA.public"));
            m_publicCAKey = (RSAPublicKey)stream.readObject();
            stream.close();
        
            new ConsoleThread().start();
        }
        catch(Exception ex) 
        {
            System.out.println("** Error starting Voter: " + ex + "\n");
            return false;
        }
        System.out.println();
        return true;
    }

    private boolean doCLARegister(String voterId)
    {
        boolean success = false;
        try 
        {
            System.out.println("### Sending data to CLA");
            window.getResultsArea().append("- Attempting retrieval of data from the Central Legitimization Agency\n\n");

            Socket socket = new Socket(m_CLAServerName, VOTER_TO_CLA_PORT);
            
            ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream input = new ObjectInputStream(socket.getInputStream());
        
            System.out.println( "~~~ Generating key with bitsize " + KEY_SIZE + " for transmission to CLA" );
            KeyGenerator kg = KeyGenerator.getInstance("Blowfish","CryptixCrypto");
            kg.init(KEY_SIZE, new SecureRandom());
            SecretKey symmetricKey = kg.generateKey();
            
            RSAPublicKey claKey = (RSAPublicKey)input.readObject();
            byte[] claCert = (byte[])input.readObject();
            
            ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
            ObjectOutputStream contentStream = new ObjectOutputStream(byteStream);
            contentStream.writeObject(claKey);
            contentStream.writeObject(new String("CLA"));
                
            Signature sig = Signature.getInstance("SHA1withRSA");
            sig.initVerify(m_publicCAKey);
            sig.update(byteStream.toByteArray());                
            if(!sig.verify(claCert))
            {
                window.getResultsArea().append("- Sorry a security check on the connection to the Central Legitimization Agency failed\n\n");
                System.out.println("** CLA certification failed\n");
                socket.close();
                return false;
            }
            else
            {
                System.out.println("~~~ CLA certificate verified");
            }
    
            contentStream.close();
            byteStream.close();

            ByteArrayOutputStream keyBytes = new ByteArrayOutputStream();
            DataOutputStream keyStream = new DataOutputStream(keyBytes);
            byte [] encodedKey = symmetricKey.getEncoded();
            keyStream.writeUTF(symmetricKey.getAlgorithm());
            keyStream.writeInt(encodedKey.length);
            keyStream.write(encodedKey, 0, encodedKey.length);
                
            System.out.println("~~~ Using CLA's public RSA key to encrypt key");
            m_pkCipher.init(Cipher.ENCRYPT_MODE, claKey);
            output.writeObject(m_pkCipher.doFinal(keyBytes.toByteArray()));

            keyStream.close();
            keyBytes.close();

            ByteArrayOutputStream requestBytes = new ByteArrayOutputStream();
            ObjectOutputStream requestStream = new ObjectOutputStream(requestBytes);
            
            System.out.println("~~~ Contacting CLA to login voter " + voterId);
            requestStream.writeObject(voterId);

            requestStream.writeObject(m_publicKey);

            System.out.println("~~~ Using key to encrypt data for CLA");
            m_cipher.init(Cipher.ENCRYPT_MODE, symmetricKey);
            byte[] encryptedRequest = m_cipher.doFinal(requestBytes.toByteArray());
            output.writeObject(encryptedRequest);
                    
            requestStream.close();

            System.out.println("~~~ Using key to decrypt data from CLA");
            m_cipher.init(Cipher.DECRYPT_MODE, symmetricKey);
            byte[] encryptedResponse = (byte[])input.readObject();
            byte[] decryptedResponse = m_cipher.doFinal(encryptedResponse);

            System.out.println("~~~ Verifying CLA signature of data from CLA");
            sig.initVerify(claKey);
            sig.update(decryptedResponse);                
            if(!sig.verify((byte[])input.readObject()))
            {
                System.out.println("** CLA signature failed\n");
                socket.close();
                return false;
            }
            else
            {
                System.out.println("~~~ CLA signature verified");
            }    

            ObjectInputStream responseStream = new ObjectInputStream(new ByteArrayInputStream(decryptedResponse));
            String responseType = (String)responseStream.readObject();
            if (responseType.equals("NEW")) 
            {
                m_validationId = (BigInteger)responseStream.readObject();
                System.out.println("~~~ Login successful, new ValidationId " + m_validationId + " received");
                window.getResultsArea().append("- New ValidationId assigned by CLA\n\n");
                success = true;
            }
            else if (responseType.equals("REPEAT"))
            {
                m_validationId = (BigInteger)responseStream.readObject();
                System.out.println("~~~ Login successful, exisiting ValidationId " + m_validationId + " received");
                window.getResultsArea().append("- Existing ValidationId retrieved by CLA\n\n");
                success = true;
            }
            else if (responseType.equals("ERROR")) 
            {
                String errorMessageString = (String)responseStream.readObject();
                System.out.println("** Error from CLA: " + errorMessageString);
                window.getResultsArea().append("- Sorry, communication with the Central Legitimization Agency resulted in the following error: " + errorMessageString + "\n\n");
            }
            else 
            {
                System.out.println("** Unknown response from CLA");
                window.getResultsArea().append("- Sorry, and unknown error occured while communicating with the Central Legitimization Agency\n\n");
            }
            System.out.println("### Done receiving response from CLA");
            responseStream.close();
            output.close();    
            socket.close();
        }
        catch(Exception ex)
        {
            if (ex.getClass().isInstance(new java.net.ConnectException())
                || ex.getClass().isInstance(new java.io.EOFException()))
            {
                window.getResultsArea().append("- Sorry, a fatal error occurred while trying to contact the Central Legitimization Agency\n\n");
                System.out.println("** Error communicating with CLA: " + ex.getMessage());
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

    private boolean doCTFRegister(String mode, BigInteger voteValidation, String candidate)
    {
        boolean success = false;
        try 
        {
            System.out.println("### Sending data to CTF");
            window.getResultsArea().append("- Attempting retrieval of data from the Central Tabulating Facility\n\n");

            Socket socket = new Socket(m_CTFServerName, VOTER_TO_CTF_PORT);
            
            ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream input = new ObjectInputStream(socket.getInputStream());
        
            System.out.println( "~~~ Generating Blowfish key with bitsize " + KEY_SIZE + " for transmission to CTF" );
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
                window.getResultsArea().append("- Sorry a security check on the connection to the Central Tabulating Facility failed\n\n");
                System.out.println("** CTF certification failed\n");
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
            
            requestStream.writeObject(m_publicKey);

            if (mode.equals("VOTE"))
            {
                System.out.println("~~~ Contacting CTF to register vote of Voter " + voteValidation + " for Candidate " + candidate);
                requestStream.writeObject(mode);
                // now write out the voter validation number
                requestStream.writeObject(voteValidation);
                // now write out the voter's selected candidate
                requestStream.writeObject(candidate);
            }
            else if (mode.equals("CHECK"))
            {
                System.out.println("~~~ Contacting CTF to verify vote for Voter " + voteValidation);
                requestStream.writeObject(mode);
                // now write out the voter validation number
                requestStream.writeObject(voteValidation);
            }
            else if (mode.equals("LIST"))
            {
                System.out.println("~~~ Contacting CTF to retrieve a list of Candidates");
                requestStream.writeObject(mode);
            }    
            else if (mode.equals("RESULTS"))
            {
                System.out.println("~~~ Contacting CTF to retrieve the results of the election");
                requestStream.writeObject(mode);
            }

            System.out.println("~~~ Using key to encrypt data for CTF");
            m_cipher.init(Cipher.ENCRYPT_MODE, symmetricKey);
            byte[] encryptedRequest = m_cipher.doFinal(requestBytes.toByteArray());
            output.writeObject(encryptedRequest);

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
                if (mode.equals("VOTE"))
                {
                    System.out.println("~~~ Vote was successfully registered");
                    window.getResultsArea().append("- Your vote has been successfully registered\n\n");
                }
                else if (mode.equals("CHECK"))
                {
                    String candidateName = (String)responseStream.readObject();
                    System.out.println("~~~ Vote was successfully verified for Candidate " + candidateName);
                    window.getResultsArea().append("- Your vote has been successfully verified\n\n");
                    window.getResultsArea().append("- The candidate you voted for was: " + candidateName + "\n\n");
                }
                else if (mode.equals("LIST"))
                {
                    System.out.println("~~~ List of candidates received");
                    m_candidateList = (Vector<?>)responseStream.readObject();
                    window.getResultsArea().append("- Received list of candidates\n\n");
                    window.displayCandidates(m_candidateList);
                }
                else if (mode.equals("RESULTS"))
                {
                    System.out.println("~~~ Results of the election received");
                    Vector<?> results = (Vector<?>)responseStream.readObject();
                    window.getResultsArea().append("- Election Results:\n");
                    for (int i = 0; i < results.size(); i++ )
                    {
                        window.getResultsArea().append("  - " + (String)results.elementAt(i) + "\n");
                    }
                    window.getResultsArea().append("\n");
                }    
            }
            else if(responseType.equals("ERROR")) 
            {
                String errorMessageString = (String)responseStream.readObject();
                System.out.println("** Error from CTF: " + errorMessageString);
                window.getResultsArea().append("- Sorry, communication with the Central Tabulating Facility resulted in the following error: " + errorMessageString + "\n\n");
            }
            else if(responseType.equals("NONE"))
            {
                System.out.println("~~~ Vote was successfully verified as unregistered");
                window.getResultsArea().append("- Your vote has not been registered with the CTF\n\n");
            }    
            else 
            {
                System.out.println("** Unknown response from CTF");
                window.getResultsArea().append("- Sorry, and unknown error occured while communicating with the Central Tabulating Facility\n\n");
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
                window.getResultsArea().append("- Sorry, a fatal error occurred while trying to contact the Central Tabulating Facility\n\n");
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
                
    private void submitVoterId()
    {
        if (window.getVoterId().length() > 0 && window.getPassword().length() >0)
        {
            m_voterId = new String(window.getVoterId() + "," + window.getPassword());
            if (!doCLARegister(m_voterId))
            {
                m_voterId = null;
            }
            else
            {
                doCTFRegister("LIST", null, null);
            }    
        }
        else
        {
            window.getResultsArea().append("- Please ensure that you have entered both a voterId and password\n\n");
        }    
    }

    private void submitCandidateId()
    {
        if (m_validationId != null)
        {
            String candidateId = null;
            if ((candidateId = window.getCandidateId()) != null)
            {
                window.getResultsArea().append("- Sending vote for candidate " + candidateId + " to the Central Tabulating Facility\n\n");
                doCTFRegister("VOTE", m_validationId, candidateId);
            }
            else
            {
                window.getResultsArea().append("- Please select a candidate before submitting your vote\n\n");
            }    
        }
        else
        {
            window.getResultsArea().append("- Please login before you vote\n\n");
        }    
    }

    private void verifyVote()
    {
        if (m_validationId != null)
        {
            doCTFRegister("CHECK", m_validationId, null);
        }
        else
        {
            window.getResultsArea().append("- Please login before you verify your vote\n\n");
        }    
    }
        
    private void voteResults()
    {
        doCTFRegister("RESULTS", null, null);
    }    

    private void logout()
    {
        m_validationId = null;
        m_voterId = null;
        window.reset();    
        window.getResultsArea().append(welcomeString);
    }

    public boolean isM_listening() {
		return m_listening;
	}

	public void setM_listening(boolean m_listening) {
		this.m_listening = m_listening;
	}

	public RSAPrivateKey getM_privateKey() {
		return m_privateKey;
	}

	public void setM_privateKey(RSAPrivateKey m_privateKey) {
		this.m_privateKey = m_privateKey;
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
                System.out.println("VoterService Closed by User...");
                System.exit(0);    
            }
            catch (Exception ex)
            {
                ex.printStackTrace();
            }    
        }
    }
}
