/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2015
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.common.test.utilities;

import java.io.IOException;
import java.security.SecureRandom;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.util.encoders.Base64;

public class RandomIDGenerator {

    public static String convertASN1OctetStringToString(final ASN1OctetString asn1OctetString) throws IOException {
        final String data = new String(Base64.encode(asn1OctetString.getOctets()));
        return data;
    }

    public static String generate() {
        final byte[] noncebytes = new byte[16];
        final SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(noncebytes);
        return new String(Base64.encode(noncebytes));
    }

}
