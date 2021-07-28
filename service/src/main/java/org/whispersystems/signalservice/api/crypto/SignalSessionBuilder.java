package org.whispersystems.signalservice.api.crypto;

import org.signal.libsignal.protocol.InvalidKeyException;
import org.signal.libsignal.protocol.SessionBuilder;
import org.signal.libsignal.protocol.UntrustedIdentityException;
import org.signal.libsignal.protocol.state.PreKeyBundle;
import org.whispersystems.signalservice.api.SignalSessionLock;
import org.signal.libsignal.protocol.logging.Log;

/**
 * A thread-safe wrapper around {@link SessionBuilder}.
 */
public class SignalSessionBuilder {
  private static final String TAG = SignalSessionBuilder.class.getSimpleName();

  private final SignalSessionLock lock;
  private final SessionBuilder    builder;

  public SignalSessionBuilder(SignalSessionLock lock, SessionBuilder builder) {
    this.lock    = lock;
    this.builder = builder;
  }

  public void process(PreKeyBundle preKey) throws InvalidKeyException, UntrustedIdentityException {
    Log.d(TAG, "SignalSessionBuilder pre-lock.acquire");
    try (SignalSessionLock.Lock unused = lock.acquire()) {
      Log.d(TAG, "SignalSessionBuilder lock acquired");
      builder.process(preKey);
      Log.d(TAG, "SignalSessionBuilder process complete");
    }
    Log.d(TAG, "SignalSessionBuilder post-try");
  }
}
