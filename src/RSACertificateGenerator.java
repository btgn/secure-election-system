
import java.io.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.Signature;

public class RSACertificateGenerator
{
	public static void main(String args[]) throws Exception
	{
		System.out.println("~~~~~~~~~~~~~~~~~~~~~~RSACertificateGenerator~~~~~~~~~~~~~~~~~~~~~~");        
		System.out.println("--------------Secure Election System----------------------");        
		System.out.println("        B Trilok G Nath, N Ravi Kanth, P Mounika");        
		System.out.println();
		System.out.println("===========================================================");

		if (args.length != 4) 
		{
			System.exit(1);
		}

		java.security.Provider prov = new cryptix.jce.provider.CryptixCrypto();
		java.security.Security.addProvider( prov );

		System.out.println("~~~ Reading private key from file: " + args[0] + "...");        
		ObjectInputStream privateStream = new ObjectInputStream (new FileInputStream(args[0]));
		RSAPrivateKey privateCAKey = (RSAPrivateKey)privateStream.readObject();
		privateStream.close();

		System.out.println("~~~ Reading SIGNEE public key from file: " + args[1] + "...");        
		ObjectInputStream publicStream = new ObjectInputStream (new FileInputStream(args[1]));
		RSAPublicKey publicSigneeKey = (RSAPublicKey)publicStream.readObject();
		publicStream.close();

		System.out.println("~~~ Creating signature for: " + args[2] + "...");
		ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
		ObjectOutputStream contentStream = new ObjectOutputStream(byteStream);
		contentStream.writeObject(publicSigneeKey);
		contentStream.writeObject(args[2]);

		Signature sig = Signature.getInstance("SHA1withRSA");
		sig.initSign(privateCAKey);
		sig.update(byteStream.toByteArray());
		byte[] cert = sig.sign();

		contentStream.close();
		byteStream.close();

		String certFileName = args[3]; 
		System.out.println("~~~ Outputting certificate to file: " + certFileName + "...");
		DataOutputStream certStream = new DataOutputStream (new FileOutputStream(certFileName, false));
		certStream.writeInt(cert.length);
		certStream.write(cert, 0, cert.length);
		certStream.close();

		System.out.println("~~~ Done...");        
	}
}
