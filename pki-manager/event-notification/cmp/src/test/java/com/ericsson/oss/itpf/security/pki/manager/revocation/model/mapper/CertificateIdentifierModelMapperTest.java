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
package com.ericsson.oss.itpf.security.pki.manager.revocation.model.mapper;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.common.cmp.revocation.model.data.RevocationRequest;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateIdentifier;

@RunWith(MockitoJUnitRunner.class)
public class CertificateIdentifierModelMapperTest {

    @InjectMocks
    CertificateIdentifierModelMapper certificateIdentifierModelMapper;

    @Mock
    CertificateIdentifier certificateIdentifier;

    @Mock
    RevocationRequest revocationServiceRequestXMLData;

    @Test
    public void testToModel() {
        certificateIdentifierModelMapper.toRevocationRequest(certificateIdentifier);
    }

    @Test
    public void testFromModel() {
        certificateIdentifierModelMapper.toCertificateIdentifier(revocationServiceRequestXMLData);

    }
}
