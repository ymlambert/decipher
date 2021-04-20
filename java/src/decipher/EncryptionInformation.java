/*
 * Copyright (C) 2012 University of Washington.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */

package decipher;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import decipher.CryptoException;

import java.util.Base64;


public class EncryptionInformation {
	
	private CipherFactory cipherFactory;
	private String base64RsaEncryptedSymmetricKey;

	public EncryptionInformation(String instanceId, PublicKey rsaPublicKey) throws CryptoException {

		try {
			// generate the symmetric key from random bits...
			SecureRandom r = new SecureRandom();
	        byte[] key = new byte[256 / 8];
	        r.nextBytes(key);
			
	        // construct the base64-encoded RSA-encrypted symmetric key
			Cipher pkCipher;
			pkCipher = Cipher.getInstance("RSA/None/OAEPWithSHA256AndMGF1Padding", "BC");
			
			// write AES key
			pkCipher.init(Cipher.ENCRYPT_MODE, rsaPublicKey);

			cipherFactory = new CipherFactory(instanceId, key);
			
			byte[] pkEncryptedKey = pkCipher.doFinal(key);
			
			base64RsaEncryptedSymmetricKey = Base64.getEncoder().encodeToString(pkEncryptedKey);
			
        } catch (NoSuchProviderException |NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            throw new IllegalArgumentException(e.getMessage());
        }
	 
	}

	
	Cipher getCipher() throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchPaddingException {
		return cipherFactory.getCipher();
	}
	
	String getBase64RsaEncryptedSymmetricKey() {
		return base64RsaEncryptedSymmetricKey;
	}
	
}
