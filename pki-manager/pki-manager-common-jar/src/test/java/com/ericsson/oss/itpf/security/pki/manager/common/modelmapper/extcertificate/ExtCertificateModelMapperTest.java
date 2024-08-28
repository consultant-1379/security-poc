package com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.extcertificate;

import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.List;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.common.model.Subject;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.data.SetUPData;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.Constants;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CAEntityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateAuthorityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateData;

@RunWith(MockitoJUnitRunner.class)
public class ExtCertificateModelMapperTest {

	@InjectMocks
	ExtCertificateModelMapper extCertificateModelMapper;

	@Mock
	Subject subject;

	@Mock
	CertificateAuthority issuer;

	@Mock
	PersistenceManager persistenceManager;

	private static SetUPData setUPData = new SetUPData();
	
	static {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

	@Test
	public void testFromObjectModel() throws CertificateException, IOException {

		final Certificate certificate = setUPData.getCertificate("certificates/ENMRootCA.crt");
		certificate.setSubject(subject);
		certificate.setIssuer(issuer);
		certificate.setId(1);
		CAEntityData caEntityData = new CAEntityData();
		CertificateAuthorityData certificateAuthorityData = new CertificateAuthorityData();
		certificateAuthorityData.getCertificateDatas();
		caEntityData.setCertificateAuthorityData(certificateAuthorityData);
		Mockito.when(persistenceManager.findEntityByName(CAEntityData.class, certificate.getIssuer().getName(), Constants.CA_NAME_PATH)).thenReturn(caEntityData);
		CertificateData certificateData = extCertificateModelMapper.fromObjectModel(certificate);
		assertEquals(1, certificateData.getId());
	}
	
	@Test
	public void testToObjectModel() throws CertificateException, IOException {
		List<CertificateData> certificateDatas = new ArrayList<CertificateData>();
		String filePath = "certificates/ENMRootCA.crt";
        CertificateData certificateData = setUPData.createCertificateData(filePath, "3454634");
        certificateDatas.add(certificateData);
        List<Certificate> certificates = extCertificateModelMapper.toObjectModel(certificateDatas);
		assertEquals(1, certificates.size());		
	}
}
