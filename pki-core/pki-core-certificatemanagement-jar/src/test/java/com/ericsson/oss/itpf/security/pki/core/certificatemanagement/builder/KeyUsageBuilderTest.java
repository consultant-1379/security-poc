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
package com.ericsson.oss.itpf.security.pki.core.certificatemanagement.builder;

import static org.junit.Assert.*;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.Extension;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.KeyUsage;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.KeyUsageType;
import com.ericsson.oss.itpf.security.pki.core.certificatemanagement.common.test.BaseTest;
import com.ericsson.oss.itpf.security.pki.core.common.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.certificateextension.InvalidKeyUsageException;

@RunWith(MockitoJUnitRunner.class)
@SuppressWarnings("PMD.UnusedPrivateField")
public class KeyUsageBuilderTest extends BaseTest {

    @InjectMocks
    private KeyUsageBuilder keyUsageBuilder;

    private KeyUsage keyUsage;

    private Extension keyUsageActual;

    private List<KeyUsageType> keyUsageType;

    private static final boolean isCritical = true;

    /**
     * Prepares initial data.
     */
    @Before
    public void setUp() {
        keyUsage = new KeyUsage();
        keyUsage.setCritical(isCritical);

        keyUsageType = new ArrayList<KeyUsageType>();
        keyUsageType.add(KeyUsageType.DIGITAL_SIGNATURE);
        keyUsageType.add(KeyUsageType.KEY_AGREEMENT);
        keyUsageType.add(KeyUsageType.CRL_SIGN);
        keyUsageType.add(KeyUsageType.NON_REPUDIATION);
        keyUsageType.add(KeyUsageType.KEY_ENCIPHERMENT);
        keyUsageType.add(KeyUsageType.DATA_ENCIPHERMENT);
        keyUsageType.add(KeyUsageType.KEY_CERT_SIGN);
        keyUsageType.add(KeyUsageType.ENCIPHER_ONLY);
        keyUsageType.add(KeyUsageType.DECIPHER_ONLY);

        keyUsage.setSupportedKeyUsageTypes(keyUsageType);
    }

    /**
     * Method to test building of {@link KeyUsage} extension.
     * 
     * @throws IOException
     *             {@link IOException}
     */
    @Test
    public void testBuildKeyUsage() throws IOException {
        keyUsageActual = keyUsageBuilder.buildKeyUsage(keyUsage);

        final DEROctetString keyUsageExpected = new DEROctetString(new org.bouncycastle.asn1.x509.KeyUsage(generateKeyUsage(keyUsage.getSupportedKeyUsageTypes())));

        assertExtensionValue(keyUsageExpected, keyUsageActual);
        assertEquals(Extension.keyUsage, keyUsageActual.getExtnId());
    }

    /**
     * Method to test building of {@link KeyUsage} with empty list of key usage types, which does not have any values in key usage extension.
     * 
     * @throws IOException
     *             {@link IOException}
     */
    @Test
    public void testBuildKeyUsageWithEmptyList() throws IOException {
        keyUsageType.clear();
        keyUsage.setSupportedKeyUsageTypes(null);

        keyUsageActual = keyUsageBuilder.buildKeyUsage(keyUsage);

        assertNotNull(keyUsageActual);
    }

    private int generateKeyUsage(final List<KeyUsageType> keyUsageTypes) {
        int keyUsage = 0;

        for (final KeyUsageType keyUsageType : keyUsageTypes) {
            keyUsage = keyUsage | getProviderKeyUsage(keyUsageType);
        }
        return keyUsage;
    }

    private int getProviderKeyUsage(final KeyUsageType keyUsageType) {
        switch (keyUsageType) {
        case DIGITAL_SIGNATURE:
            return org.bouncycastle.asn1.x509.KeyUsage.digitalSignature;
        case NON_REPUDIATION:
            return org.bouncycastle.asn1.x509.KeyUsage.nonRepudiation;
        case KEY_ENCIPHERMENT:
            return org.bouncycastle.asn1.x509.KeyUsage.keyEncipherment;
        case DATA_ENCIPHERMENT:
            return org.bouncycastle.asn1.x509.KeyUsage.dataEncipherment;
        case KEY_AGREEMENT:
            return org.bouncycastle.asn1.x509.KeyUsage.keyAgreement;
        case KEY_CERT_SIGN:
            return org.bouncycastle.asn1.x509.KeyUsage.keyCertSign;
        case CRL_SIGN:
            return org.bouncycastle.asn1.x509.KeyUsage.cRLSign;
        case ENCIPHER_ONLY:
            return org.bouncycastle.asn1.x509.KeyUsage.encipherOnly;
        case DECIPHER_ONLY:
            return org.bouncycastle.asn1.x509.KeyUsage.decipherOnly;
        default:
            throw new InvalidKeyUsageException(ErrorMessages.INVALID_KEYUSAGE_TYPE);
        }
    }
}
