/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2017
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.cdps.ejb

import java.io.FileInputStream
import java.nio.file.Path
import java.security.cert.CertificateFactory
import java.security.cert.X509CRL
import java.util.List
import com.ericsson.oss.itpf.security.pki.cdps.cdt.CACertificateInfo
import com.ericsson.oss.itpf.security.pki.cdps.cdt.CRLInfo
import com.ericsson.oss.itpf.security.pki.cdps.common.persistence.entity.CDPSEntityData
import java.nio.file.Files
import java.nio.file.Paths
/**
 * This class prepares the test data for to get the CRL's from CDPS DB. 
 * 
 * @author xchowja
 *
 */
public class TestCRLSetUpData {

	public CDPSEntityData getCRLSetUpData(final String caName,final String certSerialNumber,final String filePath) {

		final CDPSEntityData cdpsEntityData = new CDPSEntityData();
		cdpsEntityData.setCaName(caName);
		cdpsEntityData.setCertSerialNumber(certSerialNumber);
		cdpsEntityData.setCrl(getX509CRL(filePath));
		cdpsEntityData.setId(2);
		return cdpsEntityData;
	}

	public byte[] getX509CRL(final String fileName) {
		byte[] crlContent = null
		try {
			Path path = Paths.get(fileName);
			crlContent = Files.readAllBytes(path);
		}catch (Exception e) {
		}
		return crlContent;
	}

	public X509CRL getX509CRL(final byte[] crlByteArray) {
		X509CRL x509crl = null;
		try {
			final ByteArrayInputStream inputStream = new ByteArrayInputStream(crlByteArray);
			final CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
			x509crl = (X509CRL) certificateFactory.generateCRL(inputStream);
		} catch (Exception e) {
		}
		return x509crl;
	}
}
