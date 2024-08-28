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
package com.ericsson.oss.itpf.security.pki.common.test.response;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateEncodingException;

import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.cmp.*;

public interface ClientResponse {

    PKIHeader createPKIHeader(PKIMessage requestMessage) throws IOException;

    PKIBody createPKIBody(PKIMessage requestMessage) throws IOException;

    DERBitString createSignatureString(PKIHeader pkiHeader, PKIBody pkiBody) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException, IOException;

    PKIMessage createPKIMessage(PKIHeader pkiHeader, PKIBody pkiBody, DERBitString signature) throws CertificateEncodingException;

}
