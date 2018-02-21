import java.io.*;
import java.util.*;
import java.math.*;

public class SET{
    
    public static void run(){
    
        Scanner scan = new Scanner(System.in);
        System.out.println("Enter PI");
        int pi = scan.nextInt();
        BigInteger PI = BigInteger.valueOf(pi);


        System.out.println("PI: "+PI);

        System.out.println("Enter OI");
        int oi = scan.nextInt();
        BigInteger OI = BigInteger.valueOf(oi);

        System.out.println("OI: "+OI);
        
        System.out.println("Enter hashfunction addition parameter");
        int hf_add = scan.nextInt();
        BigInteger hashfunc_add = BigInteger.valueOf(hf_add);
        System.out.println("hashfunc addition parameter: "+hashfunc_add);

        System.out.println("Enter hashfunction mod parameter");
        int hf_mod = scan.nextInt();
        BigInteger hashfunc_mod = BigInteger.valueOf(hf_mod);
        System.out.println("hashfunc mod parameter: "+hashfunc_mod);

        System.out.println("HashFunction : (x + "+hashfunc_add+" ) mod "+hashfunc_mod+"");
        
        System.out.println("Enter public key e");
        int e = scan.nextInt();
        System.out.println("Enter public key n1");
        int n1 = scan.nextInt();
        System.out.println("Public Key : ("+e+","+n1+")");        
        
        System.out.println("Enter private key d");
        int d = scan.nextInt();
        System.out.println("Enter private key n2");
        int n2 = scan.nextInt();
        System.out.println("Public Key : ("+d+","+n2+")");        
        
        System.out.println("What is the Dual Signature created by Customer?");
        System.out.println("---------------");
        System.out.println("H(PI)");
        System.out.println("= ("+PI+"+"+hashfunc_add+") mod "+hashfunc_mod+" ");
        System.out.println("= ("+PI.add(hashfunc_add)+") mod "+hashfunc_mod+" ");
        BigInteger H_PI = ModularArithmetic.modadd(PI, hashfunc_add, hashfunc_mod);
        System.out.println("H(PI) : "+H_PI);

        System.out.println("---------------");

        System.out.println("H(OI)");
        System.out.println("= ("+OI+"+"+hashfunc_add+") mod "+hashfunc_mod+" ");
        System.out.println("= ("+OI.add(hashfunc_add)+") mod "+hashfunc_mod+" ");
        BigInteger H_OI = ModularArithmetic.modadd(OI, hashfunc_add, hashfunc_mod);
        System.out.println("H(OI) : "+H_OI);

        System.out.println("H(H(PI) || H(OI))");
		System.out.println("H("+H_PI+" || "+H_OI+")");
		System.out.println("H("+H_PI+""+H_OI+")");
		String h_pi_h_oi = H_PI+""+H_OI;
		BigInteger H_PI_H_OI = BigInteger.valueOf(Integer.parseInt(h_pi_h_oi));
		System.out.println("= ("+H_PI_H_OI+"+"+hashfunc_add+") mod "+hashfunc_mod+" ");
        System.out.println("= ("+H_PI_H_OI.add(hashfunc_add)+") mod "+hashfunc_mod+" ");
        BigInteger H_H_PI_H_OI = ModularArithmetic.modadd(H_PI_H_OI, hashfunc_add, hashfunc_mod);
	    System.out.println("H_H_PI_H_OI : "+H_H_PI_H_OI);

	    System.out.println("E(PRC, [H(H(PI) || H(OI))])");
        System.out.println(H_H_PI_H_OI+"^"+d+" mod "+n2);
	    // BigInteger DS = ModularArithmetic.modexp(H_H_PI_H_OI, d, n2);
	    // System.out.println(DS);
	    
	    BigInteger DS = (H_H_PI_H_OI.pow(d)).mod(BigInteger.valueOf(n2));
	    System.out.println(DS);

	    System.out.println("What information does the merchant need to know to verify the dual signature and how to verify it?");
		System.out.println("The merchant needs to know OI, PIMD, DS");
		System.out.println("H[(PIMD) || H(OI)]");
		System.out.println("H["+H_PI+" || "+H_OI+"]");
		System.out.println("H["+H_PI+""+H_OI+"]");
		System.out.println("= ("+H_PI_H_OI+"+"+hashfunc_add+") mod "+hashfunc_mod+" ");
        System.out.println("= ("+H_PI_H_OI.add(hashfunc_add)+") mod "+hashfunc_mod+" ");
        System.out.println("= "+H_H_PI_H_OI);
        System.out.println("D(PUC, DS)");
        System.out.println(DS+"^"+e+" mod "+n1);
        BigInteger D_PUC_DS = (DS.pow(e)).mod(BigInteger.valueOf(n1));
	    System.out.println(D_PUC_DS);
	    System.out.println("POMD = D(PUC, DS)\n The dual signature is verified");

	    System.out.println("What information does the bank need to know to verify the dual signature and how to verify it?");
	    System.out.println("H[H(PI) || OIMD]");
	    System.out.println("H["+H_PI+" || "+H_OI+"]");
		System.out.println("H["+H_PI+""+H_OI+"]");
		System.out.println("= ("+H_PI_H_OI+"+"+hashfunc_add+") mod "+hashfunc_mod+" ");
        System.out.println("= ("+H_PI_H_OI.add(hashfunc_add)+") mod "+hashfunc_mod+" ");
        System.out.println("= "+H_H_PI_H_OI);
        System.out.println("D(PUC, DS)");
        System.out.println(DS+"^"+e+" mod "+n1);
        BigInteger D_PUC_DS1 = (DS.pow(e)).mod(BigInteger.valueOf(n1));
	    System.out.println(D_PUC_DS1);
	    System.out.println("POMD = D(PUC, DS)\nThe dual signature is verified");
									        
    }

    public static void main(String[] args){
    	run();
    }
}

class ModularArithmetic{

	static BigInteger N;

	public static BigInteger modadd(BigInteger a, BigInteger b, BigInteger N){
		BigInteger c = a.add(b);		
		return c.mod(N);
	}

	public static BigInteger modmult(BigInteger a, BigInteger b, BigInteger N){
		BigInteger c = a.multiply(b);
		return c.mod(N);
	}
	public static BigInteger moddiv(BigInteger a, BigInteger b, BigInteger N){
		BigInteger c = a.divide(b);
		return c.mod(N);
	}

	public static BigInteger modexp(BigInteger a, int b, BigInteger N){
		BigInteger c = a.pow(b);
		return c.mod(N);
	}

	public static Boolean isPrime(BigInteger N,int k){

		double probability = 1/Math.pow(2,k);
		int prob = 2;
		if(N.isProbablePrime(prob)){
			return true;
		}
		else{
			return false;
		}

	}

	//generate n bit prime
	public static BigInteger genPrime(int n){
		N = BigInteger.probablePrime(n, new Random());
		return N;
	}
	
}