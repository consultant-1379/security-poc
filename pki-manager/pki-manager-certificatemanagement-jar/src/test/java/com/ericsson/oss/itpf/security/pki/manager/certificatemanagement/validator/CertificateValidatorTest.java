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
package com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.validator;

import static org.junit.Assert.assertEquals;

import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.CACertificateIdentifier;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.data.SetUPData;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapperv1.MappingDepth;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.CACertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.CertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.InvalidCAException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.model.certificate.DNBasedCertificateIdentifier;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateData;

@RunWith(MockitoJUnitRunner.class)
public class CertificateValidatorTest {

    @InjectMocks
    CertificateValidator certificateValidator;

    @Mock
    CACertificatePersistenceHelper caPersistenceHelper;

    @Mock
    CertificatePersistenceHelper certificatePersistenceHelper;

    @Mock
    Logger logger;

    private static SetUPData setUPData;
    private static final String validIssuerDN = "CN=ENM, OU=Ericsson, C= India";
    private static final String validSubjectDN = "CN=ENM, OU=TCS, C= India";
    private static final String serialNumber = "12et4we23";
    public static final String CERTIFICATE_STATUS_MANDATORY = "Certificate Status is Mandatory for List Issued Certificates";

    @Before
    public void setup() {

        setUPData = new SetUPData();
    }

    /**
     * Test Case for verifying issuer has active certificate.
     * 
     * @throws Exception
     */
    @Test
    public void testVerifyIssuerChain() throws Exception {

        final List<CertificateData> certificates = new ArrayList<CertificateData>();
        final CertificateData certificateData = new CertificateData();
        certificateData.setId(0);
        certificates.add(certificateData);
        Mockito.when(caPersistenceHelper.getCertificateDatas(SetUPData.ROOT_CA_NAME, CertificateStatus.ACTIVE)).thenReturn(certificates);

        certificateValidator.validateIssuerChain(SetUPData.ROOT_CA_NAME);

        Mockito.verify(caPersistenceHelper).getCertificateDatas(SetUPData.ROOT_CA_NAME, CertificateStatus.ACTIVE);

    }

    /**
     * Test Case for verifying issuer has active certificate.
     * 
     * @throws Exception
     */
    @Test(expected = InvalidCAException.class)
    public void testVerifyIssuerChain_Has_NoActiveCertificate() throws Exception {

        final List<CertificateData> certificates = new ArrayList<CertificateData>();
        Mockito.when(caPersistenceHelper.getCertificateDatas("entity", CertificateStatus.ACTIVE)).thenReturn(certificates);

        certificateValidator.validateIssuerChain(SetUPData.ROOT_CA_NAME);

        Mockito.verify(caPersistenceHelper).getCertificates(SetUPData.ROOT_CA_NAME, MappingDepth.LEVEL_0, CertificateStatus.ACTIVE);

    }

    @Test
    public void testValidateIssuer() throws Exception {

        final List<CertificateData> certificates = new ArrayList<CertificateData>();
        final CertificateData certificateData = new CertificateData();
        certificateData.setStatus(CertificateStatus.ACTIVE.getId());
        certificates.add(certificateData);
        Mockito.when(caPersistenceHelper.getCertificateDatas(SetUPData.ROOT_CA_NAME, CertificateStatus.ACTIVE)).thenReturn(certificates);

        certificateValidator.validateIssuerChain(SetUPData.ROOT_CA_NAME);

        Mockito.verify(caPersistenceHelper).getCertificateDatas(SetUPData.ROOT_CA_NAME, CertificateStatus.ACTIVE);

    }

    @Test(expected = InvalidCAException.class)
    public void testValidateIssuer_InvalidCAException() throws Exception {

        final List<CertificateData> certificates = new ArrayList<CertificateData>();
        Mockito.when(caPersistenceHelper.getCertificateDatas(SetUPData.ROOT_CA_NAME, CertificateStatus.ACTIVE)).thenReturn(certificates);

        certificateValidator.validateIssuerChain(SetUPData.ROOT_CA_NAME);
    }

    @Test(expected = CertificateServiceException.class)
    public void testValidateIssuer_CertificateServiceException() throws Exception {

        final List<CertificateData> certificates = new ArrayList<CertificateData>();
        certificates.add(new CertificateData());

        Mockito.when(caPersistenceHelper.getCertificateDatas(SetUPData.ROOT_CA_NAME, CertificateStatus.ACTIVE)).thenReturn(certificates);
        Mockito.doThrow(new CertificateServiceException()).when(certificatePersistenceHelper)
                .validateCertificateChain(certificates.get(0), EnumSet.of(CertificateStatus.REVOKED, CertificateStatus.EXPIRED));

        certificateValidator.validateIssuerChain(SetUPData.ROOT_CA_NAME);

        Mockito.verify(caPersistenceHelper).getCertificateDatas(SetUPData.ROOT_CA_NAME, CertificateStatus.ACTIVE);

    }

    @Test(expected = MissingMandatoryFieldException.class)
    public void testValidateDNBasedCertificateIdentifier() throws Exception {

        final DNBasedCertificateIdentifier dnBasedCertificateIdentifier = new DNBasedCertificateIdentifier();

        certificateValidator.validateDNBasedCertificateIdentifier(dnBasedCertificateIdentifier);
    }

    @Test(expected = MissingMandatoryFieldException.class)
    public void testValidateDNBasedCertificateIdentifier_WithIssuerDN() throws Exception {

        final DNBasedCertificateIdentifier dnBasedCertificateIdentifier = new DNBasedCertificateIdentifier();
        dnBasedCertificateIdentifier.setIssuerDN(validIssuerDN);

        certificateValidator.validateDNBasedCertificateIdentifier(dnBasedCertificateIdentifier);
    }

    @Test(expected = CANotFoundException.class)
    public void testValidateDNBasedCertificateIdentifier_CANotFoundException() throws Exception {

        final DNBasedCertificateIdentifier dnBasedCertificateIdentifier = new DNBasedCertificateIdentifier();
        certificateValidator.validateDNBasedCertificateIdentifier(dnBasedCertificateIdentifier, 0L);
    }

    @Test(expected = MissingMandatoryFieldException.class)
    public void testValidateDNBasedCertificateIdentifier_MissingMandatoryFieldException() throws Exception {

        final DNBasedCertificateIdentifier dnBasedCertificateIdentifier = new DNBasedCertificateIdentifier();
        dnBasedCertificateIdentifier.setSubjectDN(validSubjectDN);

        certificateValidator.validateDNBasedCertificateIdentifier(dnBasedCertificateIdentifier, 2L);
    }

    @Test(expected = MissingMandatoryFieldException.class)
    public void testValidateDNBasedCertificateIdentifier_MissingMandatoryFieldException_WithoutSerialNumber() throws Exception {

        final DNBasedCertificateIdentifier dnBasedCertificateIdentifier = new DNBasedCertificateIdentifier();
        dnBasedCertificateIdentifier.setSubjectDN(validSubjectDN);
        dnBasedCertificateIdentifier.setIssuerDN(validIssuerDN);

        certificateValidator.validateDNBasedCertificateIdentifier(dnBasedCertificateIdentifier, 2L);
    }

    @Test(expected = MissingMandatoryFieldException.class)
    public void testValidateDNBasedCertificateIdentifier_MissingMandatoryFieldException_WithoutIssuerDN() throws Exception {

        final DNBasedCertificateIdentifier dnBasedCertificateIdentifier = new DNBasedCertificateIdentifier();
        dnBasedCertificateIdentifier.setSubjectDN(validSubjectDN);
        dnBasedCertificateIdentifier.setCerficateSerialNumber(serialNumber);

        certificateValidator.validateDNBasedCertificateIdentifier(dnBasedCertificateIdentifier, 2L);
    }

    @Test(expected = MissingMandatoryFieldException.class)
    public void testValidateDNBasedCertificateIdentifier_MissingMandatoryFieldException_WithoutSubjectDN() throws Exception {

        final DNBasedCertificateIdentifier dnBasedCertificateIdentifier = new DNBasedCertificateIdentifier();
        dnBasedCertificateIdentifier.setIssuerDN(validIssuerDN);
        dnBasedCertificateIdentifier.setCerficateSerialNumber(serialNumber);

        certificateValidator.validateDNBasedCertificateIdentifier(dnBasedCertificateIdentifier, 2L);
    }

    @Test(expected = MissingMandatoryFieldException.class)
    public void testValidateCACertificateIdentifier_WithoutIdentifier() throws Exception {

        final CACertificateIdentifier caCertificateIdentifier = new CACertificateIdentifier();

        certificateValidator.validateCACertificateIdentifier(caCertificateIdentifier, CertificateStatus.ACTIVE);
    }

    @Test(expected = CertificateNotFoundException.class)
    public void testValidateCACertificateIdentifier_WithoutCertificateCount() throws Exception {

        final CACertificateIdentifier caCertificateIdentifier = new CACertificateIdentifier();

        certificateValidator.validateCACertificateIdentifier(caCertificateIdentifier, 0);
    }

    @Test(expected = CertificateNotFoundException.class)
    public void testValidateCACertificateIdentifier_WithoutSerialNumber() throws Exception {

        final CACertificateIdentifier caCertificateIdentifier = new CACertificateIdentifier();

        certificateValidator.validateCACertificateIdentifier(caCertificateIdentifier, 2);
    }

    @Test
    public void testValidateIssuerChainInvalidCAException() {

        final List<CertificateData> certificates = new ArrayList<CertificateData>();
        Mockito.when(caPersistenceHelper.getCertificateDatas("entity", CertificateStatus.ACTIVE)).thenReturn(certificates);

        final String expectedErrorMessage = "Could not issue certificate because CAEntity " + SetUPData.ROOT_CA_NAME + " does not have an ACTIVE certificate";

        try {
            certificateValidator.validateIssuerChain(SetUPData.ROOT_CA_NAME);
        } catch (InvalidCAException invalidCAException) {
            assertEquals(expectedErrorMessage, invalidCAException.getMessage());
        }

    }
}
