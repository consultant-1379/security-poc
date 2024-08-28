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
package com.ericsson.oss.itpf.security.pki.ra.scep.validator;

import java.security.Security;
import java.util.ArrayList;
import java.util.List;

import javax.cache.Cache;

import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.junit.*;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.cache.annotation.NamedCache;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.model.AlgorithmType;
import com.ericsson.oss.itpf.security.pki.common.util.StringUtility;
import com.ericsson.oss.itpf.security.pki.ra.scep.builder.Pkcs7ScepRequestSetUpData;
import com.ericsson.oss.itpf.security.pki.ra.scep.data.Pkcs7ScepRequestData;
import com.ericsson.oss.itpf.security.pki.ra.scep.exception.*;

/**
 * This class tests algorithmValidator
 */
@RunWith(MockitoJUnitRunner.class)
public class AlgorithmValidatorTest {

    @Mock
    private SystemRecorder systemRecorder;

    @Mock
    @NamedCache("SupportedAlgorithmsCache")
    private Cache<String, List<String>> cache;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }
    private String successPkcs = "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";
    private CMSSignedData cmsSignedData;
    private byte[] message = null;
    private SignedData signedData;

    @InjectMocks
    AlgorithmValidator algorithmValidator;

    @Mock
    Logger logger;

    private Pkcs7ScepRequestData pkcs7RequestData;

    private List<String> suppAlgorithms;

    /**
     * setUp method initializes the required data which are used as a part of the test cases.
     */
    @Before
    public void setUp() {
        message = successPkcs.getBytes();
        if (StringUtility.isBase64(new String(message))) {
            message = Base64.decode(message);
        }
        try {
            cmsSignedData = new CMSSignedData(message);
        } catch (final CMSException e) {
            Assert.fail(e.getMessage());
        }
        signedData = SignedData.getInstance(cmsSignedData.toASN1Structure().getContent());
        pkcs7RequestData = Pkcs7ScepRequestSetUpData.getPkcs7ScepRequest(message);
        suppAlgorithms = new ArrayList<String>();
        suppAlgorithms.add("1.3.14.3.2.26");
        suppAlgorithms.add("1.2.840.113549.1.1.1");
        suppAlgorithms.add("1.2.840.113549.1.1.1");
        suppAlgorithms.add("1.3.14.3.2.6");
        suppAlgorithms.add("1.3.14.3.2.7");
        suppAlgorithms.add("1.3.14.3.2.8");
        suppAlgorithms.add("1.3.14.3.2.9");
        suppAlgorithms.add("1.3.14.3.2.17");
        suppAlgorithms.add("1.3.6.1.4.1.4929.1.6");
        suppAlgorithms.add("1.2.840.113549.3.7");
        suppAlgorithms.add("1.2.840.113549.1.1.5");
    }

    /**
     * This method tests if supported algorithm is not present in cache
     */
    @Test(expected = SupportedAlgsNotFoundException.class)
    public void testvalidateSignedDataDigestAlg_failure() {
        algorithmValidator.validateSignedDataDigestAlg(signedData);
    }

    /**
     * This method Tests SupportedAlgorithms
     */
    @Test
    public void testValidateSignatureAlgorithm() {
        Mockito.when(cache.get(AlgorithmType.MESSAGE_DIGEST_ALGORITHM.value())).thenReturn(suppAlgorithms);
        Mockito.when(cache.get(AlgorithmType.ASYMMETRIC_KEY_ALGORITHM.value())).thenReturn(suppAlgorithms);
        algorithmValidator.validateSignatureAlgorithm(pkcs7RequestData);
    }

    /**
     * This method Tests UnSupportedAlgorithms received in request.
     */
    @Test(expected = UnSupportedAlgException.class)
    public void testUnsupportedSignatureAlgorithm() {
        final List<String> supportedAlgorithms = new ArrayList<String>();
        Mockito.when(cache.get(AlgorithmType.MESSAGE_DIGEST_ALGORITHM.value())).thenReturn(supportedAlgorithms);
        Mockito.when(cache.get(AlgorithmType.ASYMMETRIC_KEY_ALGORITHM.value())).thenReturn(supportedAlgorithms);
        algorithmValidator.validateSignatureAlgorithm(pkcs7RequestData);
    }

    /**
     * This method tests MessageDigestAlgorithms
     */
    @Test
    public void testValidateSignedDataDigestAlg() {
        Mockito.when(cache.get(AlgorithmType.MESSAGE_DIGEST_ALGORITHM.value())).thenReturn(suppAlgorithms);
        algorithmValidator.validateSignedDataDigestAlg(signedData);
    }

    /**
     * This method tests isSupportedAlgorithm with null algorithm OID
     */
    @Test(expected = BadRequestException.class)
    public void testBadRequestException() {
        Mockito.when(cache.get(AlgorithmType.ASYMMETRIC_KEY_ALGORITHM.value())).thenReturn(suppAlgorithms);
        algorithmValidator.isSupportedAlgorithm(null, "Null algorithm OID", AlgorithmType.ASYMMETRIC_KEY_ALGORITHM);
    }

    /**
     * This method tests exception scenario of ValidateSignedDataDigestAlg
     */
    @Test(expected = UnSupportedAlgException.class)
    public void testValidateSignedDataDigestAlgExce() {
        suppAlgorithms = new ArrayList<String>();
        suppAlgorithms.add("1.2.3.4");
        Mockito.when(cache.get(AlgorithmType.MESSAGE_DIGEST_ALGORITHM.value())).thenReturn(suppAlgorithms);
        algorithmValidator.validateSignedDataDigestAlg(signedData);
    }

}
