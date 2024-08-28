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
package com.ericsson.oss.itpf.security.pki.manager.test.setup;

/**
 * This is SetUp Class for CrlGenerationInfo.
 */
import java.util.ArrayList;
import java.util.List;

import javax.xml.datatype.*;

import com.ericsson.oss.itpf.security.pki.common.model.Algorithm;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.crl.CRLVersion;
import com.ericsson.oss.itpf.security.pki.common.model.crl.CrlGenerationInfo;
import com.ericsson.oss.itpf.security.pki.common.model.crl.extension.CrlExtensions;

public class CrlGenerationInfoSetUpData {
	
	private static CrlExtensions crlExtensions=new CrlExtensions(); 
	private static Algorithm signatureAlgorithm=new Algorithm();
	private static Duration duration=null;
	
	/**
	 * Method to set values to CrlGenerationInfo for equal case. 
	 * @return CrlGenerationInfo.
	 */
	
	public static CrlGenerationInfo getCrlGenerationInfoEqual() throws DatatypeConfigurationException{ 
		final CrlGenerationInfo CrlGenerationInfo=new CrlGenerationInfo();
		List<Certificate> caCertificates=new ArrayList<Certificate>();
		caCertificates.add(null);
		CrlGenerationInfo.setCaCertificates(caCertificates);
		CrlGenerationInfo.setCrlExtensions(crlExtensions);
	    duration = DatatypeFactory.newInstance().newDuration("P42D");
		CrlGenerationInfo.setOverlapPeriod(duration);
		CrlGenerationInfo.setSignatureAlgorithm(signatureAlgorithm);
		CrlGenerationInfo.setSkewCrlTime(duration);
		CrlGenerationInfo.setValidityPeriod(duration);
		CrlGenerationInfo.setVersion(CRLVersion.V2);
		CrlGenerationInfo.setId(1);
		return CrlGenerationInfo;
		
	} 
	
	/**
	 * Method to set values to CrlGenerationInfo for Not equal case.
	 * @return CrlGenerationInfo.
	 */
	public static CrlGenerationInfo getCrlGenerationInfoNotEqual() throws DatatypeConfigurationException{
		final CrlGenerationInfo CrlGenerationInfo=new CrlGenerationInfo();
		List<Certificate> caCertificates=new ArrayList<Certificate>();
		CrlGenerationInfo.setCaCertificates(caCertificates);
		CrlGenerationInfo.setCrlExtensions(crlExtensions);
		CrlGenerationInfo.setOverlapPeriod(duration);
		CrlGenerationInfo.setSignatureAlgorithm(signatureAlgorithm);
		CrlGenerationInfo.setSkewCrlTime(duration);
		CrlGenerationInfo.setValidityPeriod(duration);
		CrlGenerationInfo.setVersion(CRLVersion.V2);
		CrlGenerationInfo.setId(3);
		return CrlGenerationInfo;
		
	}
	
	
}
