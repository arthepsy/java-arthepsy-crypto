package eu.arthepsy.crypto.internal;

import javax.crypto.spec.PBEKeySpec;
import java.security.spec.KeySpec;

public final class PBENullSaltKeySpec implements KeySpec {
    private PBEKeySpec _base = null;
    private boolean _emptySalt = false;

    public PBENullSaltKeySpec(PBEKeySpec keySpec) {
        _base = keySpec;
    }

    public PBENullSaltKeySpec(char[] password) {
        _base = new PBEKeySpec(password);
    }

    public PBENullSaltKeySpec(char[] password, byte[] salt, int iterationCount, int keyLength) {
        if (salt == null || salt.length == 0) {
            _emptySalt = true;
        }
        _base = new PBEKeySpec(password, (_emptySalt ? new byte[password.length] : salt), iterationCount, keyLength);
    }

    public PBENullSaltKeySpec(char[] password, byte[] salt, int iterationCount) {
        if (salt == null || salt.length == 0) {
            _emptySalt = true;
        }
        _base = new PBEKeySpec(password, (_emptySalt ? new byte[password.length] : salt), iterationCount);
    }
    public final void clearPassword() {
        _base.clearPassword();
    }
    public final char[] getPassword() {
        return _base.getPassword();
    }
    public final byte[] getSalt() {
        if (_emptySalt) {
            return null;
        } else {
            return _base.getSalt();
        }
    }
    public final int getIterationCount() {
        return _base.getIterationCount();
    }
    public final int getKeyLength() {
        return _base.getKeyLength();
    }
}
