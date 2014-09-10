package eu.arthepsy.crypto;

import eu.arthepsy.crypto.internal.*;
import javax.crypto.SecretKeyFactory;
import javax.crypto.SecretKeyFactorySpi;
import java.lang.reflect.Constructor;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;

public class Hash {
    private static final Provider _provider = getProvider();
    private static final String _providerPrefix = "SecretKeyFactory.";
    private static final String _pbkdf2algorithmPrefix = "PBKDF2WithHmac";
    private static final String _pbkdf2classPrefix = "eu.arthepsy.crypto.internal.PBKDF2Core";

    private static Provider getProvider() {
        Provider provider =  Security.getProvider("SunJCE");
        String[] sha = {"SHA1", "SHA224", "SHA256", "SHA384", "SHA512"};
        for (String s: sha) {
            provider.put(_providerPrefix + _pbkdf2algorithmPrefix + s, _pbkdf2classPrefix + "$Hmac" + s);
        }
        return provider;
    }

    public static String CreatePBKDF2Sha1Hash(String password, String salt, Integer iterations, Integer keySize) {
        return CreatePBKDF2Hash(_pbkdf2algorithmPrefix + "SHA1", password, salt, iterations, keySize);
    }
    public static String CreatePBKDF2Sha2Hash(Integer hashBits, String password, String salt, Integer iterations, Integer keySize) throws IllegalArgumentException {
        if (hashBits == 224 || hashBits == 256 || hashBits == 384 || hashBits == 512) {
            return CreatePBKDF2Hash(_pbkdf2algorithmPrefix + "SHA" + hashBits.toString(), password, salt, iterations, keySize);
        } else {
            throw new IllegalArgumentException("SHA algorithm bits not valid");
        }
    }

    private static String CreatePBKDF2Hash(String algorithm, String password, String salt, Integer iterations, Integer keySize) {
        byte[] raw_salt = (salt != null && salt.length() > 0 ? salt.getBytes() : null);
        PBENullSaltKeySpec spec = new PBENullSaltKeySpec(password.toCharArray(), raw_salt, iterations, keySize);
        try {
            SecretKeyFactory skf = getSecretKeyFactory(algorithm);
            byte[] hash = skf.generateSecret(spec).getEncoded();
            return bytesToHexString(hash);
        } catch (Exception e) {
            return null;
        }
    }

    @SuppressWarnings("unchecked")
    private static SecretKeyFactory getSecretKeyFactory(String algorithm) throws NoSuchAlgorithmException {
        try {
            Class<SecretKeyFactorySpi> spiClass = (Class<SecretKeyFactorySpi>) Class.forName((String) _provider.get(_providerPrefix + algorithm));
            SecretKeyFactorySpi spi = spiClass.newInstance();
            Constructor<SecretKeyFactory> c = SecretKeyFactory.class.getDeclaredConstructor(SecretKeyFactorySpi.class, Provider.class, String.class);
            c.setAccessible(true);
            return c.newInstance(spi, _provider, algorithm);
        } catch (Exception e) {
            throw new NoSuchAlgorithmException(e);
        }
    }

    private static String bytesToHexString(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for(byte b : bytes){
            sb.append(String.format("%02x", b&0xff));
        }
        return sb.toString();
    }

}
