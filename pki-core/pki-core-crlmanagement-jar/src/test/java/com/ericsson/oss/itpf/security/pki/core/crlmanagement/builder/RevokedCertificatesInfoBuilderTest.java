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
package com.ericsson.oss.itpf.security.pki.core.crlmanagement.builder;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.persistence.EntityManager;
import javax.persistence.Query;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.core.crlmanagement.common.test.BaseTest;
import com.ericsson.oss.itpf.security.pki.core.crlmanagement.common.test.CRLSetUpData;
import com.ericsson.oss.itpf.security.pki.core.crlmanagement.crlgenerator.RevokedCertificatesInfo;

/**
 * Test Class for RevokedCertificatesInfoBuilder.
 */
@RunWith(MockitoJUnitRunner.class)
public class RevokedCertificatesInfoBuilderTest extends BaseTest {

    @InjectMocks
    RevokedCertificatesInfoBuilder revokedCertificatesInfoBuilder;

    @Mock
    Logger logger;

    @Mock
    PersistenceManager persistenceManager;

    @Mock
    Query revokedCertificatesQuery;

    @Mock
    static Query revocationRequestIdNativeQuery;

    @Mock
    EntityManager entityManager;

    private static Certificate issuerCertificate;
    private static List<Object[]> revokedCertificates = new ArrayList<Object[]>();
    private static Date date;
	private static final String CRLEXTENSION = "{\"invalidityDate\":{\"invalidityDate\":null},\"reasonCode\":{\"revocationReason\":\"UNSPECIFIED\"}}";

    /**
     * Prepares initial Data.
     */
    @Before
    public void setUpData() {
        date = CRLSetUpData.getNextAfter();
        issuerCertificate = CRLSetUpData.getCertificate();
        Object[] object = new Object[] { "", date, CRLEXTENSION };
        revokedCertificates.add(object);
    }

    /**
     * Method to test buildRevokedCertificateInfo .
     */
    @SuppressWarnings("unchecked")
    @Test
    public void testBuildRevokedCertificateInfo() {
        Mockito.when(persistenceManager.getEntityManager()).thenReturn(entityManager);
        Mockito.when(entityManager.createNativeQuery(Mockito.anyString())).thenReturn(revokedCertificatesQuery);
        Mockito.when(revokedCertificatesQuery.getResultList()).thenReturn(revokedCertificates);
    	
        List<RevokedCertificatesInfo> ExpectedRevokedCertificatesInfoList = revokedCertificatesInfoBuilder.buildRevokedCertificateInfo(issuerCertificate);

        assertNotNull(ExpectedRevokedCertificatesInfoList);
        assertEquals(1, ExpectedRevokedCertificatesInfoList.size());
    }
}
