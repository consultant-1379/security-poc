package com.ericsson.oss.iptf.security.credmsapi.test;

import static org.junit.Assert.assertTrue;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import com.ericsson.oss.iptf.security.credmsapi.test.utils.KeyAndCertUtil;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.IssueCertificateException;
import com.ericsson.oss.itpf.security.credmsapi.business.handlers.CsrHandler;

@RunWith(JUnit4.class)
public class CsrUnitTest {

	String signatureAlgorithmString = "SHA256WithRSAEncryption";
	CsrHandler csrHandler = new CsrHandler();
	PKCS10CertificationRequest pkcs10Csr = null;
	KeyAndCertUtil kSTestUtil = new KeyAndCertUtil();

	@SuppressWarnings("static-access")
        @Test
	public void testCreateCsr() {

	    kSTestUtil.prepareParameters();

		/*
		 * Invoke getCsr method of CsrHandler class
		 */
		try {
			pkcs10Csr = csrHandler.getCSR(kSTestUtil.endEntity, signatureAlgorithmString,
			        kSTestUtil.keyPair, kSTestUtil.derAttributes);
		} catch (IssueCertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		assertTrue("Csr Request was not created correctly", pkcs10Csr != null);

		ASN1Primitive pk = null;
		pk = pkcs10Csr.getSubjectPublicKeyInfo().getPublicKeyData(); //getSubjectPublicKeyInfo().getPublicKey(); (deprecated)
		assertTrue("Csr does not contain the public key", pk != null);

	}

}
