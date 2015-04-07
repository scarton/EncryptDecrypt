package com.rsc.encdec;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.commons.cli.BasicParser;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * @author steve
 *
 */
public class EncryptDecrypt {
	
	private static byte[] encrypt(PublicKey publicKey, byte[] in) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
	    Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding");   
	    cipher.init(Cipher.ENCRYPT_MODE, publicKey);  
	    return cipher.doFinal(in);
	}

	private static byte[] decrypt(PrivateKey privateKey, byte[] out) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
	    Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding");   
	    cipher.init(Cipher.DECRYPT_MODE, privateKey);  
	    return cipher.doFinal(out);	
	}
	
	public static void writeFileBytes(String filename, byte[] bytes) throws IOException
	{
	    Path path = Paths.get(filename);
	    Files.write(path, bytes, StandardOpenOption.CREATE);        
	}
	
	public static byte[] readFileBytes(String filename) throws IOException
	{
	    Path path = Paths.get(filename);
	    return Files.readAllBytes(path);        
	}
	
	public static PublicKey readPublicKey(String filename) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException
	{
	    X509EncodedKeySpec publicSpec = new X509EncodedKeySpec(readFileBytes(filename));
	    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
	    return keyFactory.generatePublic(publicSpec);       
	}

	public static PrivateKey readPrivateKey(String filename) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException
	{
		Security.addProvider(new BouncyCastleProvider());
	    PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(readFileBytes(filename));
	    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
	    return keyFactory.generatePrivate(keySpec);     
	}	
	
	/**
	 * -o operation,
	 * -k key file (private or public for decryption or encryption)
	 * -f Source or target file to encrypt or decrypt
	 *
	 * @param args
	 * @throws IOException 
	 * @throws InvalidKeySpecException 
	 * @throws NoSuchAlgorithmException 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * @throws NoSuchPaddingException 
	 * @throws InvalidKeyException 
	 * @throws ParseException 
	 */
	public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		Options opts = new Options();
		Option o = new Option("e", true, "Operation - enc or dec");
		o.setRequired(true);
		opts.addOption(o);
		o = new Option("k", true, "Key File: Full path, public for encryption, private for decryption.");
		o.setRequired(true);
		opts.addOption(o);
		o = new Option("i", true, "Input File: full path.");
		o.setRequired(true);
		opts.addOption(o);
		o = new Option("o", true, "Output File: full path.");
		o.setRequired(true);
		opts.addOption(o);
		CommandLineParser clp = new BasicParser();
		CommandLine cmd = null;
		try {
			cmd = clp.parse(opts, args);
		} catch (ParseException e) {
			new HelpFormatter().printHelp("EncryptDecrypt", opts);
			System.exit(0);
		}
		String op = cmd.getOptionValue("e").toLowerCase();
		if (!op.equals("enc") && !op.equals("dec")) {
			System.out.println("-e option must be either 'enc' or 'dec'.");
			new HelpFormatter().printHelp("EncryptDecrypt", opts);
			System.exit(0);
		}
		String kf = cmd.getOptionValue("k");
		if (kf.length()==0 || !new File(kf).exists() || !new File(kf).isFile())
		{
			System.out.println("-k option must point to a valid key file.");
			new HelpFormatter().printHelp("EncryptDecrypt", opts);
			System.exit(0);
		}
		String fi = cmd.getOptionValue("i");
		if (fi.length()==0 || !new File(fi).exists() || !new File(fi).isFile())
		{
			System.out.println("-i option must point to a valid source file.");
			new HelpFormatter().printHelp("EncryptDecrypt", opts);
			System.exit(0);
		}
		String fo = cmd.getOptionValue("o");
		if (fo.length()==0)
		{
			System.out.println("-o option must point to a valid output file name which will be overwritten if it exists.");
			new HelpFormatter().printHelp("EncryptDecrypt", opts);
			System.exit(0);
		}
		
		byte[] src = readFileBytes(fi);
		if (op.equals("enc")) {
			PublicKey publicKey = readPublicKey(kf);
			writeFileBytes(fo, encrypt(publicKey, src));
		} else {
			PrivateKey privateKey = readPrivateKey(kf);
			writeFileBytes(fo, decrypt(privateKey, src));
		}
	}

}

