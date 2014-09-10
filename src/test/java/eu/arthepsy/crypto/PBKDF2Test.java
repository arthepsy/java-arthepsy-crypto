package eu.arthepsy.crypto;

import static eu.arthepsy.crypto.Hash.CreatePBKDF2Sha2Hash;
import org.testng.annotations.Test;

public class PBKDF2Test {

    @Test
    public void testEmptySaltHash() {
        String hash = CreatePBKDF2Sha2Hash(256, "test123", null, 100000, 256);
        assert hash.equals("5f2553c5117132d51af0924da70c6ed0119ff419ff08f087b7f71eb3aa7dacae");
    }

    @Test
    public void testWithSha256Hash() {
        String hash = CreatePBKDF2Sha2Hash(256, "test123", "test123", 100000, 256);
        assert hash.equals("dd8e192cb3373f71783f9a3b146231f71b0397b949b67d3e38d733b11d0f7884");
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testInvalidSha2Bits() {
        String hash = CreatePBKDF2Sha2Hash(123, "test123", null, 100000, 256);
    }
}
