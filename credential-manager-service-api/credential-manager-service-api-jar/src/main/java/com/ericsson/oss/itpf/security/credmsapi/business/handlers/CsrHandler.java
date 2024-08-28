/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2012
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.credmsapi.business.handlers;

import java.security.KeyPair;

import org.bouncycastle.asn1.x509.Attribute;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.IssueCertificateException;
import com.ericsson.oss.itpf.security.credmsapi.business.utils.CertificateUtils;
import com.ericsson.oss.itpf.security.credmsapi.business.utils.ErrorMsg;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerEntity;

public class CsrHandler {

	private static final Logger LOG = LogManager.getLogger(CsrHandler.class);
	
	public PKCS10CertificationRequest getCSR(
			final CredentialManagerEntity eentity,
			final String signatureAlgorithm, final KeyPair keyPair,
			final Attribute[] attributes) 
			        throws IssueCertificateException {
		try {
			final PKCS10CertificationRequest csr = CertificateUtils
					.generatePKCS10Request(signatureAlgorithm, eentity,
							keyPair, (attributes));
			return csr;

		} catch (final Exception e) {
			LOG.error(ErrorMsg.API_ERROR_HANDLERS_CREATE_PKCS10CSR,eentity.getName());

			throw new IssueCertificateException("generatePKCS10Request error", e);
		}

	}

}
