
public class ServiceProvider
{    
    public static void main(String args[]) throws Exception
    {
        if (args.length == 0)
        {
            System.out.println("~~~~~~~~~~~~~~~~~~~~~~ServiceProvider~~~~~~~~~~~~~~~~~~~~~~");        
            System.out.println("--------------Secure Election System----------------------");        
            System.out.println("        B Trilok G Nath, N Ravi Kanth, P Mounika");        
            System.out.println();
            System.out.println(" Enter q at the beginning of a line and hit enter to quit");
            System.out.println("===========================================================");
            System.out.println("Usage:\nServiceProvider <ServiceName> <Parameters for ServiceName>");        
            System.exit(1);
        }                            
        
        String newArgs[] = new String[args.length-1];
        for (int i=1; i<args.length; i++)
        {
            newArgs[i-1] = args[i];
        }
        if (args[0].equals("CTFService"))
        {
            CTFService.main(newArgs);
        }
        else if(args[0].equals("CLAService"))
        {
            CLAService.main(newArgs);
        }
        else if(args[0].equals("VoterService"))
        {
            VoterService.main(newArgs);
        }
        else if(args[0].equals("RSACertificateGenerator"))
        {
            RSACertificateGenerator.main(newArgs);
        }
        else if(args[0].equals("RSACertificateVerifier"))
        {
            RSACertificateVerifier.main(newArgs);
        }
        else if(args[0].equals("RSAKeyGenerator"))
        {
            RSAKeyGenerator.main(newArgs);
        }    
        else
        {
            System.out.println("Unrecognized service!");
        }        
    }
}