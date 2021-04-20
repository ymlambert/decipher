package decipher;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import decipher.CryptoException;
import decipher.DecryptionInformation;
import decipher.EncryptionInformation;

public class malakit_cipher {

	static final String UTF_8 = "UTF-8";
	static final String ENCRYPTED_FILE_EXTENSION = ".enc";
	static final String MISSING_FILE_EXTENSION = ".missing";

	public static void main(String[] args) {

		Security.addProvider(new BouncyCastleProvider());
		
		
		if(args[0].equals("decipher")) {
			String pathEncryptedFile = args[1];
			String base64EncryptedSymmetricKey = args[2]; 
			String instanceId = args[3];
			String base64RsaPrivateKey = args[4];
		
			File encryptedFile = new File(pathEncryptedFile);

			try {			
				PrivateKey rsaPrivateKey = makePrivateKey(base64RsaPrivateKey);
				DecryptionInformation ei = new DecryptionInformation(base64EncryptedSymmetricKey, instanceId, rsaPrivateKey);	
				String dec = decryptFile(ei, encryptedFile);
				System.out.println(dec);

			} catch (InvalidKeySpecException | InvalidKeyException | NoSuchPaddingException | InvalidAlgorithmParameterException
					| NoSuchAlgorithmException | IOException | CryptoException e) {
				System.err.println(e.toString());
			}		
		}
		else if(args[0].equals("cipher")) {
		
			String pathDecryptedFile = args[1];
			String instanceId = args[2];
			String formId = args[3];
			String formVersion = args[4];
			String base64RsaPublicKey = args[5];
			
			File decryptedFile = new File(pathDecryptedFile);


			try {			
				PublicKey rsaPublicKey = makePublicKey(base64RsaPublicKey);
				
				EncryptionInformation ei = new EncryptionInformation(instanceId, rsaPublicKey);
				encryptFile(ei, decryptedFile);
				
				String base64RsaEncryptedSymmetricKey = ei.getBase64RsaEncryptedSymmetricKey();
				String base64EncryptedElementSignature = getBase64EncryptedElementSignature(formId, formVersion, base64RsaEncryptedSymmetricKey, instanceId, rsaPublicKey);
				
				StringBuilder output = new StringBuilder();
				output.append("{");
				output.append("\"formId\":");
				output.append("\"").append(formId).append("\"");
				output.append(",");
				output.append("\"formVersion\":");
				output.append("\"").append(formVersion).append("\"");
				output.append(",");
				output.append("\"instanceId\":");
				output.append("\"").append(instanceId).append("\"");
				output.append(",");
				output.append("\"base64RsaEncryptedSymmetricKey\":");
				output.append("\"").append(base64RsaEncryptedSymmetricKey).append("\"");
				output.append(",");
				output.append("\"base64EncryptedElementSignature\":");
				output.append("\"").append(base64EncryptedElementSignature).append("\"");
				output.append("}");
				
				System.out.println(output.toString());

			} catch (InvalidKeySpecException | NoSuchAlgorithmException | IOException | CryptoException e) {
				System.err.println(e.toString());
			}	
		}

	}
		
	private static PublicKey makePublicKey(String base64RsaPublicKey) 
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		PublicKey rsaPublicKey;

		byte[] byteRsaPublicKey = Base64.getDecoder().decode(base64RsaPublicKey); 
		X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(byteRsaPublicKey);

		KeyFactory kf;
		kf = KeyFactory.getInstance("RSA");
		rsaPublicKey = kf.generatePublic(publicKeySpec);

		return rsaPublicKey;
	}
	
	private static void encryptFile(EncryptionInformation ei, File file)
            throws IOException, CryptoException {
       
		File encryptedFile = new File(file.getParentFile(), file.getName() + ".enc");

        if (encryptedFile.exists() && !encryptedFile.delete()) {
            throw new IOException("Cannot overwrite " + encryptedFile.getAbsolutePath()
                    + ". Perhaps the file is locked?");
        }

        RandomAccessFile randomAccessFile = null;
        CipherOutputStream cipherOutputStream = null;
        try {
            Cipher c = ei.getCipher();
        	
            randomAccessFile = new RandomAccessFile(encryptedFile, "rws");
            ByteArrayOutputStream encryptedData = new ByteArrayOutputStream();
            cipherOutputStream = new CipherOutputStream(encryptedData, c);
            InputStream fin = new FileInputStream(file);
            byte[] buffer = new byte[2048];
            int len = fin.read(buffer);
            while (len != -1) {
                cipherOutputStream.write(buffer, 0, len);
                len = fin.read(buffer);
            }
            fin.close();
            cipherOutputStream.flush();
            cipherOutputStream.close();

            randomAccessFile.write(encryptedData.toByteArray());

            //Timber.i("Encrpyted:%s -> %s", file.getName(), encryptedFile.getName());
        } catch (Exception e) {
            String msg = "Error encrypting: " + file.getName() + " -> "
                    + encryptedFile.getName();
            //Timber.e(e, "%s due to %s ", msg, e.getMessage());
            throw new CryptoException(msg);
        } finally {
        		randomAccessFile.close();
        }
        
    }
	
    private static String getBase64EncryptedElementSignature(String formId, String formVersion, 
    		String base64RsaEncryptedSymmetricKey, String instanceId, PublicKey rsaPublicKey) {
    	    	
    		// Creation of elementSignatureSource
        // Step 0: construct the text of the elements in elementSignatureSource (done)
        //     Where...
        //      * Elements are separated by newline characters.
        //      * Filename is the unencrypted filename (no .enc suffix).
        //      * Md5 hashes of the unencrypted files' contents are converted
        //        to zero-padded 32-character strings before concatenation.
        //      Assumes this is in the order:
        //          formId
        //          version   (omitted if null)
        //          base64RsaEncryptedSymmetricKey
        //          instanceId
        //          for each media file { filename "::" md5Hash }
        //          submission.xml "::" md5Hash
	    StringBuilder elementSignatureSource = new StringBuilder();
		elementSignatureSource.append(formId).append("\n");
		elementSignatureSource.append(formVersion).append("\n");
        	elementSignatureSource.append(base64RsaEncryptedSymmetricKey).append("\n");
		elementSignatureSource.append(instanceId).append("\n");

        // Step 1: construct the (raw) md5 hash of Step 0.
        byte[] messageDigest;
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            md.update(elementSignatureSource.toString().getBytes(UTF_8));
            messageDigest = md.digest();
        } catch (NoSuchAlgorithmException | UnsupportedEncodingException e) {
            throw new IllegalArgumentException(e.getMessage());
        }

        // Step 2: construct the base64-encoded RSA-encrypted md5
        try {
            Cipher pkCipher;
            pkCipher = Cipher.getInstance("RSA/NONE/OAEPWithSHA256AndMGF1Padding");
            // write AES key
            pkCipher.init(Cipher.ENCRYPT_MODE, rsaPublicKey);
            byte[] pkEncryptedKey = pkCipher.doFinal(messageDigest);
            return Base64.getEncoder().encodeToString(pkEncryptedKey);

        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            throw new IllegalArgumentException(e.getMessage());
        }
    }

	
    
    
	private static PrivateKey makePrivateKey(String base64RsaPrivateKey) 
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		PrivateKey rsaPrivateKey;

		byte[] byteRsaPrivateKey = Base64.getDecoder().decode(base64RsaPrivateKey); 
		PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(byteRsaPrivateKey);

		KeyFactory kf;
		kf = KeyFactory.getInstance("RSA");
		rsaPrivateKey = kf.generatePrivate(privateKeySpec);

		return rsaPrivateKey;
	}

	private static final String decryptFile(DecryptionInformation ei, File original)
			throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException {

		Cipher c = ei.getCipher();

		try (InputStream fin = new CipherInputStream(new FileInputStream(original), c);
				OutputStream fout = new ByteArrayOutputStream();
				){
			byte[] buffer = new byte[2048];
			int len = fin.read(buffer);
			while (len != -1) {
				fout.write(buffer, 0, len);
				len = fin.read(buffer);
			}

			String dec = fout.toString();
			fout.flush();
			fin.close();

			return dec;
		}
	}
	

}
