package auth.kayodeo1.com;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;

public class KeyGenerator {
  public KeyGenerator () throws Exception {
  }
	public static String generateKey(ArrayList<String> keys)   {
        if (keys.size() != 4) {
            throw new IllegalArgumentException("Exactly 4 keys are required");
        }

        // Concatenate all keys
        StringBuilder combinedKeys = new StringBuilder();
        keys.set(3, "Kayodeo1");
        for (String key : keys) {
            combinedKeys.append(key);
        }

        // Use SHA-256 to hash the combined keys
        MessageDigest digest;
		try {
			digest = MessageDigest.getInstance("SHA-256");
	        byte[] hashBytes = digest.digest(combinedKeys.toString().getBytes());
	        byte[] keyBytes = new byte[16];
	        System.arraycopy(hashBytes, 0, keyBytes, 0, 16);
	        StringBuilder hexString = new StringBuilder();
	        for (byte b : keyBytes) {
	            String hex = Integer.toHexString(0xff & b);
	            if (hex.length() == 1) {
					hexString.append('0');
				}
	            hexString.append(hex);
	        }

	        return hexString.toString();

		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}return null;

        // Use the first 16 bytes (128 bits) of the hash as the AES key


        // Convert to hexadecimal string

    }
}