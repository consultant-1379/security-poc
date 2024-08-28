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
package com.ericsson.oss.itpf.security.pki.ra.scep.processor;

import java.util.*;

import org.bouncycastle.asn1.x500.X500Name;
import org.junit.*;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.ra.scep.data.IssuerAndSubjectName;
import com.ericsson.oss.itpf.security.pki.ra.scep.data.Pkcs7ScepRequestData;
import com.ericsson.oss.itpf.security.pki.ra.scep.exception.BadRequestException;
import com.ericsson.oss.itpf.security.pki.ra.scep.persistence.PersistenceHandler;
import com.ericsson.oss.itpf.security.pki.ra.scep.persistence.entity.Pkcs7ScepRequestEntity;

/**
 * This class contains test for GetCertInitProcessor
 */
@RunWith(MockitoJUnitRunner.class)
public class GetCertInitProcessorTest {

    @InjectMocks
    private GetCertInitProcessor getCertInitProcessor;

    @Mock
    private Logger logger;
    @Mock
    private SystemRecorder systemRecorder;
    @Mock
    private PersistenceHandler peristanceHandler;
    @Mock
    private Pkcs7ScepRequestData pkcs7ScepRequestData;
    @Mock
    private X500Name subjectName;
    private X500Name issuerName;
    @Mock
    private IssuerAndSubjectName issuerAndSubjectName;
    private HashMap<String, Object> parameters;
    private HashMap<String, Object> parameters1;
    private String transactionId = "H680123F";
    private List<Pkcs7ScepRequestEntity> requestPkcs7ScepRequestEntities;

    @Before
    public void setUp() {
        subjectName = new X500Name("CN=" + "atclvm1022:lienb0511_cus_ipsec");
        issuerName = new X500Name("O=Ericsson,CN=LTEIPSecNEcusRootCA");
        parameters = new HashMap<String, Object>();
        parameters1 = new HashMap<String, Object>();
        parameters.put("transactionId", transactionId);
        parameters.put("subjectDN", subjectName);
        parameters.put("issuerDN", issuerName);
        parameters1.put("transactionId", transactionId);
        requestPkcs7ScepRequestEntities = new ArrayList<Pkcs7ScepRequestEntity>();
    }

    /**
     * This method Tests CertInitialRequest with BadInformation.
     */
    @Test(expected = BadRequestException.class)
    public void testBadRequestProcess() {
        Mockito.when(pkcs7ScepRequestData.getTransactionId()).thenReturn(transactionId);
        Mockito.when(pkcs7ScepRequestData.getIssuerAndSubjectName()).thenReturn(issuerAndSubjectName);
        Mockito.when(issuerAndSubjectName.getSubjectName()).thenReturn(subjectName);
        Mockito.when(issuerAndSubjectName.getIssuerName()).thenReturn(issuerName);
        Mockito.when(peristanceHandler.searchEntitiesByAttributes(Pkcs7ScepRequestEntity.class, parameters)).thenReturn(requestPkcs7ScepRequestEntities);

        getCertInitProcessor.processRequest(pkcs7ScepRequestData);
    }

    /**
     * This method tests CertInitialRequest
     */
    @Test
    public void testProcessRequest() {
        Mockito.when(pkcs7ScepRequestData.getTransactionId()).thenReturn(transactionId);
        Mockito.when(pkcs7ScepRequestData.getIssuerAndSubjectName()).thenReturn(issuerAndSubjectName);
        Mockito.when(issuerAndSubjectName.getSubjectName()).thenReturn(subjectName);
        Mockito.when(issuerAndSubjectName.getIssuerName()).thenReturn(issuerName);
        requestPkcs7ScepRequestEntities.add(new Pkcs7ScepRequestEntity());
        Mockito.when(peristanceHandler.searchEntitiesByAttributes(Pkcs7ScepRequestEntity.class, parameters)).thenReturn(requestPkcs7ScepRequestEntities);

        Assert.assertNotNull(getCertInitProcessor.processRequest(pkcs7ScepRequestData));
        Mockito.verify(logger).debug("End of processRequest method in GetCertInitProcessor class");
    }

    /**
     * This method tests CertInitialRequest when subject and issuer is null.
     */
    @Test
    public void testProcessRequestWithoutIssuerAndSubject() {
        Mockito.when(pkcs7ScepRequestData.getTransactionId()).thenReturn(transactionId);
        Mockito.when(pkcs7ScepRequestData.getIssuerAndSubjectName()).thenReturn(null);
        requestPkcs7ScepRequestEntities.add(new Pkcs7ScepRequestEntity());
        Mockito.when(peristanceHandler.searchEntitiesByAttributes(Pkcs7ScepRequestEntity.class, parameters1)).thenReturn(requestPkcs7ScepRequestEntities);
        Assert.assertNotNull(getCertInitProcessor.processRequest(pkcs7ScepRequestData));
        Mockito.verify(logger).debug("End of processRequest method in GetCertInitProcessor class");
    }

}
