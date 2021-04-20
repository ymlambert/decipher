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
import java.security.PrivateKey;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import decipher.CryptoException;

import java.util.Base64;


public class DecryptionInformation {
	
	private CipherFactory cipherFactory;

	public DecryptionInformation(String base64EncryptedSymmetricKey, String instanceId, PrivateKey rsaPrivateKey) throws CryptoException {

		try {
			// construct the base64-encoded RSA-encrypted symmetric key
			Cipher pkCipher;
			pkCipher = Cipher.getInstance("RSA/None/OAEPWithSHA256AndMGF1Padding", "BC");
			
			// write AES key
			pkCipher.init(Cipher.DECRYPT_MODE, rsaPrivateKey);

			byte[] encryptedSymmetricKey = Base64.getDecoder().decode(base64EncryptedSymmetricKey);
			byte[] decryptedKey = pkCipher.doFinal(encryptedSymmetricKey);
			cipherFactory = new CipherFactory(instanceId, decryptedKey);
		} catch (NoSuchProviderException | NoSuchAlgorithmException | BadPaddingException | IllegalBlockSizeException | InvalidKeyException
				| NoSuchPaddingException e) {
			String msg = "Error decrypting base64EncryptedKey";
			throw new CryptoException(msg + " Cause: " + e.toString());
		}
	}

	
	Cipher getCipher() throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchPaddingException {
		return cipherFactory.getDecipher();
	}
}
