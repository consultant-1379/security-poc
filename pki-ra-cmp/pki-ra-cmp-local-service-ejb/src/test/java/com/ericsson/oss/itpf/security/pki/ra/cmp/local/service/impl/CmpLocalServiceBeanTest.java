/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2016
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.ra.cmp.local.service.impl;

import java.io.FileNotFoundException;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.ra.cmp.local.service.impl.CMPLocalServiceBean;
import com.ericsson.oss.itpf.security.pki.ra.cmp.persistence.MessageStatus;
import com.ericsson.oss.itpf.security.pki.ra.cmp.persistence.PersistenceHandler;

@RunWith(MockitoJUnitRunner.class)
public class CmpLocalServiceBeanTest {

    @InjectMocks
    CMPLocalServiceBean cmpLocalServiceBean;

    @Mock
    Logger logger;

    @Mock
    PersistenceHandler persistenceHandler;

    final byte[] responseMessageFromManager = null;
    final String transactionID = "";
    final String senderName = "";
    final MessageStatus status = MessageStatus.WAIT_FOR_ACK;

    @Test
    public void testCmpLocalServiceBean() throws CertificateException, FileNotFoundException, CRLException {
        cmpLocalServiceBean.updateCMPTransactionStatus(transactionID, senderName, responseMessageFromManager, status, null);
    }

    @Test
    public void testCmpLocalServiceBeanSenderNonce() throws CertificateException, FileNotFoundException, CRLException {
        cmpLocalServiceBean.updateCMPTransactionStatus(transactionID, senderName, responseMessageFromManager, "senderNonce", null);

    }
}
