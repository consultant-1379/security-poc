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
package com.ericsson.oss.itpf.security.pki.ra.cmp.validator.vc;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.Set;

import org.bouncycastle.asn1.cmp.PKIMessage;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.cmp.model.RequestMessage;
import com.ericsson.oss.itpf.security.pki.common.test.request.generator.RequestGeneratorFactory;
import com.ericsson.oss.itpf.security.pki.common.test.request.main.*;
import com.ericsson.oss.itpf.security.pki.common.util.PKIXCertificatePathBuilder;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.util.TrustStoreUtil;
import com.ericsson.oss.itpf.security.pki.ra.cmp.test.utils.BaseDigitalSignatureValidatorTestUtil;

@RunWith(MockitoJUnitRunner.class)
public class DigitalSignatureValidatorTest {

    @InjectMocks
    DigitalSignatureValidator digitalSignatureValidator;

    @Mock
    PKIXCertificatePathBuilder pKIXCertificatePathBuilder;

    @Mock
    Logger logger;

    @Mock
    TrustStoreUtil trustStore;

    private static RequestMessage pKIRequestMessage;
    private static Set<X509Certificate> vendorCertificateSet = null;

    @BeforeClass
    public static void prepareTestData() throws IOException {

        final Parameters requestParameters = AbstractMain.configureParameters(null);
    	final PKIMessage pkiRequestMessage = RequestGeneratorFactory.getRequestGenerator(RequestType.INITIALIZATION_REQUEST).generate(requestParameters, null);
        pKIRequestMessage = new RequestMessage(pkiRequestMessage.getEncoded());
        vendorCertificateSet = BaseDigitalSignatureValidatorTestUtil.getVendorCerts();

    }

    @Test
    public void testValidate() throws Exception {

        Mockito.when(trustStore.getTrustedCertsBasedOnRequestType(pKIRequestMessage)).thenReturn(vendorCertificateSet);

        digitalSignatureValidator.validate(pKIRequestMessage);

        Mockito.verify(trustStore).getTrustedCertsBasedOnRequestType(pKIRequestMessage);

    }

}
