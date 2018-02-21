
import java.net.*;

import java.io.*;
import java.util.*;
import javax.crypto.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.Signature;
import java.math.BigInteger;
import javax.crypto.spec.SecretKeySpec;
 
public class CTFService
{
    public static final int CTF_PORT = 7677;

    private RSAPublicKey m_publicKey = null;

    private RSAPrivateKey m_privateKey = null;

    private RSAPublicKey m_publicCAKey = null;
    
    private byte[] m_publicKeyCert;

    private Hashtable<BigInteger, String> m_voterList = new Hashtable<BigInteger, String>();
    
    private Vector<String> m_candidateList = new Vector<String>();
    
    private boolean m_listening = false;

    public static void main(String args[]) throws Exception
    {
        System.out.println("~~~~~~~~~~~~~~~~~~~~~~CTFService~~~~~~~~~~~~~~~~~~~~~~");        
        System.out.println("--------------Secure Election System----------------------");        
        System.out.println("        B Trilok G Nath, N Ravi Kanth, P Mounika");        
        System.out.println();
        System.out.println(" Enter q at the beginning of a line and hit enter to quit");
        System.out.println("===========================================================");
                    
        CTFService ctfService = new CTFService();
        if(!ctfService.start())
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
        
            System.out.println("~~~ Reading CTF public key from file: CTF.public...");        
            ObjectInputStream stream = new ObjectInputStream (new FileInputStream("CTF.public"));
            m_publicKey = (RSAPublicKey)stream.readObject();
            stream.close();

            System.out.println("~~~ Reading CTF private key from file: CTF.private...");        
            stream = new ObjectInputStream (new FileInputStream("CTF.private"));
            m_privateKey = (RSAPrivateKey)stream.readObject();
            stream.close();

            System.out.println("~~~ Reading certificate from file: CTF.cert...");        
            DataInputStream certStream = new DataInputStream (new FileInputStream("CTF.cert"));
            int certLength = certStream.readInt();
            m_publicKeyCert = new byte[certLength];
            certStream.read(m_publicKeyCert, 0, m_publicKeyCert.length);
            certStream.close();

            stream = new ObjectInputStream (new FileInputStream("CA.public"));
            m_publicCAKey = (RSAPublicKey)stream.readObject();
            stream.close();

            System.out.println("~~~ Reading list of voters from: CTF.candidates...");        
            BufferedReader candStream = new BufferedReader (new FileReader("CTF.candidates"));
            String candidate;
            while ((candidate = candStream.readLine()) != null) 
            {
                candidate = candidate.trim();
                if (candidate.length() > 0) 
                {
                    System.out.println("   ~~~ Adding candidate: " + candidate);        
                    m_candidateList.add(candidate);
                }
            }
            
            System.out.println("~~~ Starting CTF service on port " + CTF_PORT + "...");        
            ServerSocket serverSocket = new ServerSocket(CTF_PORT);
            m_listening = true;

            System.out.println("~~~ Waiting for voter registrations...\n");        
            new ConsoleThread().start();
            while (m_listening)
                new CTFServerThread(serverSocket.accept()).start();
    
            serverSocket.close();
        }
        catch(Exception ex) 
        {
            System.out.println("** Error starting CTF: " + ex + "\n");
            return false;
        }
        return true;
    }
    
    class CTFServerThread extends Thread
    {
        private Cipher m_pkCipher = null;

        private Cipher m_cipher = null;

        private Socket m_socket = null;

        public CTFServerThread(Socket socket)
        {
            m_socket = socket;
        }
        
        public void run()
        {
            try 
            {
                System.out.println("### Received data from sender");
                m_pkCipher = Cipher.getInstance( "RSA/ECB/PKCS#1", "CryptixCrypto" );
                m_cipher = Cipher.getInstance( "Blowfish/ECB/PKCS#5", "CryptixCrypto" );

                ObjectOutputStream output = new ObjectOutputStream(m_socket.getOutputStream());
                ObjectInputStream input = new ObjectInputStream(m_socket.getInputStream());
                
                output.writeObject(m_publicKey);
                output.writeObject(m_publicKeyCert);
                
                System.out.println("~~~ Using private RSA key to decrypt key from sender");
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

                System.out.println("~~~ Using key to decrypt data from sender");
                byte[] encryptedRequest = (byte[])input.readObject();
                m_cipher.init(Cipher.DECRYPT_MODE, symmetricKey);
                byte[] decryptedRequest = m_cipher.doFinal(encryptedRequest);
                
                ObjectInputStream requestStream = new ObjectInputStream(new ByteArrayInputStream(decryptedRequest));
                RSAPublicKey userKey = (RSAPublicKey)requestStream.readObject();
                String request = (String)requestStream.readObject();
                
                ByteArrayOutputStream responseBytes = new ByteArrayOutputStream();
                ObjectOutputStream responseStream = new ObjectOutputStream(responseBytes);
                
                if (request.equals("ADD")) 
                {
                    byte [] cert = (byte [])requestStream.readObject();
                    BigInteger voterValidation = (BigInteger)requestStream.readObject();
                    byte [] userSig = (byte [])input.readObject();

                    System.out.println("~~~ Contacted by CLA to add new ValidationId " + voterValidation);
                    System.out.println("~~~ Verifying CLA's signature of data from CLA");

                    ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
                    ObjectOutputStream contentStream = new ObjectOutputStream(byteStream);
                    contentStream.writeObject(userKey);
                    contentStream.writeObject(new String("CLA"));
                        
                    Signature sig = Signature.getInstance("SHA1withRSA");
                    sig.initVerify(m_publicCAKey);
                    sig.update(byteStream.toByteArray());
                    
                    Signature sigCert = Signature.getInstance("SHA1withRSA");
                    sigCert.initVerify(userKey);
                    sigCert.update(decryptedRequest);
                                        
                    if (sig.verify(cert) && sigCert.verify(userSig)) 
                    {    
                        System.out.println("~~~ CLA certificate and signature verified");                                                
                    
                        m_voterList.put(voterValidation, new String(""));
                        responseStream.writeObject(new String("OK"));
                    }
                    else 
                    {
                        System.out.println("** CLA certificate or signature invalid");
                        responseStream.writeObject(new String("ERROR"));
                        responseStream.writeObject(new String("Certificate or Signature Invalid"));                                
                    }
                    
                    contentStream.close();
                    byteStream.close();
                }
                else if (request.equals("LIST"))
                {
                    System.out.println("~~~ Contacted by Voter to get candidate list");
                    responseStream.writeObject(new String("OK"));
                    responseStream.writeObject(m_candidateList);
                }
                else if (request.equals("VOTE"))
                {
                    BigInteger voterValidation = (BigInteger)requestStream.readObject();
                    String candidate = (String)requestStream.readObject();
                    System.out.println("~~~ Contacted by Voter " + voterValidation + " to submit vote for " + candidate);

                    if (m_candidateList.contains(candidate)) 
                    {
                        if (m_voterList.get(voterValidation) != null) 
                        {
                            String currentVote = (String)m_voterList.get(voterValidation);
                            
                            if (currentVote.length() <= 0) 
                            {
                                System.out.println("~~~ Accepted Voter's vote");
                                m_voterList.put(voterValidation, candidate);
                                responseStream.writeObject(new String("OK"));
                            }
                            else 
                            {
                                System.out.println("~~~ Voter's vote already cast");
                                responseStream.writeObject(new String("ERROR"));
                                responseStream.writeObject(new String("Vote already cast"));                                                        
                            }
                        }
                        else 
                        {
                            System.out.println("~~~ Invalid ValidationId");
                            responseStream.writeObject(new String("ERROR"));
                            responseStream.writeObject(new String("Validation Number Invalid"));                                
                        }
                    }
                    else 
                    {
                        System.out.println("~~~ Invalid Candidate");
                        responseStream.writeObject(new String("ERROR"));
                        responseStream.writeObject(new String("Invalid Candidate"));                                
                    }
                }
                else if (request.equals("CHECK"))
                {
                    BigInteger voterValidation = (BigInteger)requestStream.readObject();
                    System.out.println("~~~ Contacted by Voter " + voterValidation + " to verify vote");

                    String candidate = (String)m_voterList.get(voterValidation);
                    if (candidate != null && candidate.length() > 0) 
                    {
                        System.out.println("~~~ Vote for Voter " + voterValidation + " is registered for " + candidate);
                        responseStream.writeObject(new String("OK"));
                        responseStream.writeObject(candidate);
                    }
                    else 
                    {
                        System.out.println("~~~ No vote has been recorded for Voter " + voterValidation);
                        responseStream.writeObject(new String("NONE"));
                    }
                }
                else if (request.equals("RESULTS"))
                {
                    System.out.println("~~~ Contacted by Voter for election results");
                    int numCandidates = m_candidateList.size();
                    Vector<String> electionResults = new Vector<String>();
                    for(int i = 0; i < numCandidates; i++) 
                    {
                        String currentCandidateId = (String)m_candidateList.elementAt(i);
                        int currentCandidateVoteCount = 0;
                        Collection<String> votes = m_voterList.values();
                        Iterator<String> voteIterator = votes.iterator();
                        while (voteIterator.hasNext())
                        {
                            if (currentCandidateId.equals((String)voteIterator.next()))
                            {
                                currentCandidateVoteCount++;
                            }
                        }
                        electionResults.add(new String(currentCandidateId + ": " + currentCandidateVoteCount));
                    }    
                    responseStream.writeObject(new String("OK"));
                    responseStream.writeObject(electionResults);
                }
                else 
                {
                    responseStream.writeObject(new String("ERROR"));
                    responseStream.writeObject(new String("unknown request"));
                }
                
                requestStream.close();
                
                responseStream.writeObject(new Long(System.currentTimeMillis()));
                
                System.out.println("~~~ Using key to encrypt data for response to sender");
                m_cipher.init(Cipher.ENCRYPT_MODE, symmetricKey);
                byte[] encryptedResponse = m_cipher.doFinal(responseBytes.toByteArray());
                output.writeObject(encryptedResponse);
                
                System.out.println("~~~ Generating and sending an RSA signature of the data in the response");
                Signature sig = Signature.getInstance("SHA1withRSA");
                sig.initSign(m_privateKey);
                sig.update(responseBytes.toByteArray());
                output.writeObject(sig.sign());
                
                System.out.println("### Done sending response to sender");
                responseStream.close();
                responseBytes.close();
                input.close();
                output.close();
                m_socket.close();
            }
            catch(Exception ex)
            {
                System.out.println("** Error communicating with sender: " + ex);
                try
                {
                    m_socket.close();
                }
                catch(java.io.IOException ioe)
                {
                    ioe.printStackTrace();
                }    
            }
            System.out.println();
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
                System.out.println("CTFService Closed by User...");
                System.exit(0);    
            }
            catch (Exception ex)
            {
                ex.printStackTrace();
            }    
        }
    }
}
