package org.bouncycastle.pqc.crypto.test;

import java.security.SecureRandom;

/**
 * Implementation of null PRNG returning zeroes only.
 * For testing purposes only(!).
 * 
 * @author Sebastian Roland <seroland86@gmail.com>
 */
public class NullPRNG extends SecureRandom {

	private static final long serialVersionUID = 1L;

	public NullPRNG() {
		super();
	}
	
	@Override
	public void nextBytes(byte[] bytes) {
		;
	}
}
