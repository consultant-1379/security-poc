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
package com.ericsson.oss.itpf.security.pki.ra.cmp.revocation;

import java.io.IOException;

import org.bouncycastle.asn1.cmp.CertConfirmContent;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.cmp.model.RequestMessage;
import com.ericsson.oss.itpf.security.pki.common.cmp.model.exception.MessageParsingException;
import com.ericsson.oss.itpf.security.pki.common.util.exception.CertificateParseException;
import com.ericsson.oss.itpf.security.pki.common.util.exception.InvalidCertificateVersionException;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.util.CertConfStatusUtil;
import com.ericsson.oss.itpf.security.pki.ra.cmp.persistence.MessageStatus;
import com.ericsson.oss.itpf.security.pki.ra.cmp.persistence.PersistenceHandler;
import com.ericsson.oss.itpf.security.pki.ra.cmp.persistence.entities.CMPMessageEntity;

@RunWith(PowerMockRunner.class)
@PrepareForTest(CertConfStatusUtil.class)
public class RevocationHelperTest {

    @InjectMocks
    RevocationHelper revocationHelper;

    @Mock
    RequestMessage RequestMessage;

    @Mock
    RequestMessage pKIMessage;

    @Mock
    PersistenceHandler persistenceHandler;

    @Mock
    CertConfirmContent certConfirmContent;

    @Mock
    CMPMessageEntity protocolMessageEntity;

    @Mock
    Logger logger;

    @Test
    public void testUpdateRevocationStatus() throws MessageParsingException, CertificateParseException, InvalidCertificateVersionException, IOException {
        MessageStatus certConfStatus = MessageStatus.DONE;
        PowerMockito.mockStatic(CertConfStatusUtil.class);
        Mockito.when(CertConfStatusUtil.get(RequestMessage)).thenReturn(certConfStatus);
        Mockito.when(persistenceHandler.fetchEntityByTransactionIdAndEntityName(RequestMessage.getBase64TransactionID(), RequestMessage.getSenderName())).thenReturn(protocolMessageEntity);
        revocationHelper.updateRevocationStatus(RequestMessage);
        Mockito.verify(persistenceHandler).updateEntityStatus(protocolMessageEntity, MessageStatus.REVOCATION_IN_PROGRESS_FOR_OLD_CERTIFICATE);
    }

    @Test
    public void testUpdateRevocationStatusTO_BE_REVOKED() throws MessageParsingException, CertificateParseException, InvalidCertificateVersionException, IOException {
        MessageStatus certConfStatus = MessageStatus.TO_BE_REVOKED;
        PowerMockito.mockStatic(CertConfStatusUtil.class);
        Mockito.when(CertConfStatusUtil.get(RequestMessage)).thenReturn(certConfStatus);
        Mockito.when(persistenceHandler.fetchEntityByTransactionIdAndEntityName(RequestMessage.getBase64TransactionID(), RequestMessage.getSenderName())).thenReturn(protocolMessageEntity);
        revocationHelper.updateRevocationStatus(RequestMessage);
        Mockito.verify(persistenceHandler).updateEntityStatus(protocolMessageEntity, MessageStatus.REVOCATION_IN_PROGRESS_FOR_NEW_CERTIFICATE);
    }

    @Test
    public void testUpdateRevocationStatusForDefault() throws MessageParsingException, CertificateParseException, InvalidCertificateVersionException, IOException {
        MessageStatus certConfStatus = MessageStatus.FAILED;
        PowerMockito.mockStatic(CertConfStatusUtil.class);
        Mockito.when(CertConfStatusUtil.get(RequestMessage)).thenReturn(certConfStatus);
        revocationHelper.updateRevocationStatus(RequestMessage);
        Mockito.verify(logger).info("Certificate need not be revoked, since status could be DONE for IR");
    }
}
