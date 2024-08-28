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
package com.ericsson.oss.itpf.security.pki.manager.revocation.validator;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;

import javax.persistence.PersistenceException;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.CertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.manager.exception.revocation.InvalidInvalidityDateException;
import com.ericsson.oss.itpf.security.pki.manager.exception.revocation.RevocationServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.RevokedCertificateException;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateData;

@RunWith(MockitoJUnitRunner.class)
public class RevocationValidatorTest {

    @InjectMocks
    RevocationValidator revocationValidator;

    @Mock
    Logger logger;

    @Mock
    PersistenceManager persistenceManager;

    @Mock
    CertificatePersistenceHelper certificatePersistenceHelper;

    @Mock
    private SystemRecorder systemRecorder;

    private static CertificateData certificateData;
    private static CertificateData certificateData_issuer;
    private static List<CertificateData> cerDataList;
    private Date date;
    private Map<String, Object> mapCertificate;

    /**
     * Test method to setup data
     */
    @Before
    public void setUp() {

        certificateData_issuer = new CertificateData();
        certificateData_issuer.setId(22222);
        certificateData_issuer.setIssuedTime(date);
        certificateData_issuer.setStatus(CertificateStatus.ACTIVE.getId());

        certificateData = new CertificateData();
        certificateData.setId(1010110);
        certificateData.setIssuedTime(date);
        certificateData.setStatus(CertificateStatus.ACTIVE.getId());
        certificateData.setIssuerCertificate(certificateData_issuer);

        cerDataList = new LinkedList<CertificateData>();
        cerDataList.add(certificateData);

        date = new Date();

        mapCertificate = new HashMap<String, Object>();
        mapCertificate.put("id", certificateData.getIssuerCertificate().getId());

    }

    /**
     * Test method for {@link com.ericsson.oss.itpf.security.pki.manager.revocation.validator.RevocationValidator#validateCertificateChain(java.util.List)}.
     */
    @Test
    public void testValidateIssuerCertificateStatus() {

        Mockito.when(persistenceManager.findEntitiesWhere(CertificateData.class, mapCertificate)).thenReturn(cerDataList);
        revocationValidator.validateCertificateChain(cerDataList);
    }

    /**
     * Method to test ValidateIssuerCertificateStatus for RevocationServiceException case.
     */
    @Test(expected = RevocationServiceException.class)
    public void testValidateIssuerCertificateStatus_PersistenceException() {

        Mockito.when(persistenceManager.findEntitiesWhere(CertificateData.class, mapCertificate)).thenReturn(cerDataList);
        Mockito.doThrow(new PersistenceException()).when(certificatePersistenceHelper).validateCertificateChain(certificateData, EnumSet.of(CertificateStatus.REVOKED));

        revocationValidator.validateCertificateChain(cerDataList);
    }

    /**
     * method testvalidateInvalidityDate to test with invalidity date
     */
    @Test(expected = InvalidInvalidityDateException.class)
    public void testvalidateInvalidityDate() throws ParseException {
        final String before = "01/01/2016";
        final String after = "01/01/2025";
        final String date = "01/01/2999";
        SimpleDateFormat sd = new SimpleDateFormat("MM/dd/yyyy");
        Date dateFormat = sd.parse(before);

        certificateData.setNotBefore(dateFormat);
        dateFormat = sd.parse(after);
        certificateData.setNotAfter(dateFormat);
        dateFormat = sd.parse(date);

        revocationValidator.validateInvalidityDate(cerDataList, dateFormat);
    }

    @Test
    public void testvalidateCertificateChainForRevokedCertificate_RevocationServiceException() {
        Mockito.when(persistenceManager.findEntitiesWhere(CertificateData.class, mapCertificate)).thenThrow(new PersistenceException());
        revocationValidator.validateCertificateChain(cerDataList);
    }

    @Test(expected = RevokedCertificateException.class)
    public void testvalidateCertificateChainForRevokedCertificate_RevocationServiceException_condition() {

        certificateData.setStatus(CertificateStatus.REVOKED.getId());

        Mockito.when(persistenceManager.findEntitiesWhere(CertificateData.class, mapCertificate)).thenReturn(cerDataList);
        Mockito.doThrow(new RevokedCertificateException("Issuer Certificate is revoked")).when(certificatePersistenceHelper)
                .validateCertificateChain(certificateData, EnumSet.of(CertificateStatus.REVOKED));
        revocationValidator.validateCertificateChain(cerDataList);
    }

}
