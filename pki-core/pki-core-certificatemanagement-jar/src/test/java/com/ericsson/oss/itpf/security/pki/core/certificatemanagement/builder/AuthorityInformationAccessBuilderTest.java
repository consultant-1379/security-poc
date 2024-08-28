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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.*;
import com.ericsson.oss.itpf.security.pki.core.certificatemanagement.common.test.BaseTest;

@RunWith(MockitoJUnitRunner.class)
@SuppressWarnings("PMD.UnusedPrivateField")
public class AuthorityInformationAccessBuilderTest extends BaseTest {

    @InjectMocks
    private AuthorityInformationAccessBuilder authorityInformationAccessBuilder;

    private AccessDescription accessDescription;
    private List<AccessDescription> accessDescriptionList;
    private AuthorityInformationAccess authorityInformationAccess;
    private Extension authorityInformationAccessExtensionActual;

    private static final boolean isCrtical = true;

    private static final String OCSP_URL = "http://www.ocsp.com";

    private static final String CA_ISSUER_URL = "http://www.caissuer.com";

    /**
     * Preparing the initial data
     */
    @Before
    public void setUp() {
        authorityInformationAccess = new AuthorityInformationAccess();
        accessDescriptionList = new ArrayList<AccessDescription>();
        accessDescription = new AccessDescription();
    }

    /**
     * Test method for building {@link AuthorityInformationAccessBuilder} extension with access method OCSP.
     * 
     * @throws IOException
     *             {@link IOException}
     */
    @Test
    public void testBuildAuthorityInformationAccessByOCSP() throws IOException {
        setOCSPUrls();

        authorityInformationAccessExtensionActual = authorityInformationAccessBuilder.buildAuthorityInformationAccess(authorityInformationAccess);

        final DEROctetString authorityInformationAccessExpected = new DEROctetString(new DERSequence(addAccessDescriptionstoAIA(authorityInformationAccess)));

        assertExtensionValue(authorityInformationAccessExpected, authorityInformationAccessExtensionActual);
        assertEquals(Extension.authorityInfoAccess, authorityInformationAccessExtensionActual.getExtnId());

        accessDescriptionList.clear();
    }

    /**
     * Test method for building {@link AuthorityInformationAccessBuilder} extension with access method CA_ISSUER.
     * 
     * @throws IOException
     *             {@link IOException}
     */
    @Test
    public void testBuildAuthorityInformationAccessByCAIssuer() throws IOException {
        setCAIssuerUrls();

        authorityInformationAccessExtensionActual = authorityInformationAccessBuilder.buildAuthorityInformationAccess(authorityInformationAccess);

        final DEROctetString authorityInforamtionAccessExpected = new DEROctetString(new DERSequence(addAccessDescriptionstoAIA(authorityInformationAccess)));

        assertExtensionValue(authorityInforamtionAccessExpected, authorityInformationAccessExtensionActual);
        assertEquals(Extension.authorityInfoAccess, authorityInformationAccessExtensionActual.getExtnId());
    }

    /**
     * Test method for building {@link AuthorityInformationAccessBuilder} extension with empty list to test the negative scenario.
     * 
     * @throws IOException
     *             {@link IOException}
     */
    @Test
    public void testAuthorityInformationAccess_IOException() throws IOException {
        accessDescriptionList.clear();
        authorityInformationAccessExtensionActual = authorityInformationAccessBuilder.buildAuthorityInformationAccess(authorityInformationAccess);

        assertNull(authorityInformationAccessExtensionActual);
    }

    private void setOCSPUrls() {
        accessDescription.setAccessLocation(OCSP_URL);
        accessDescription.setAccessMethod(AccessMethod.OCSP);
        accessDescriptionList.add(accessDescription);
        authorityInformationAccess.setCritical(isCrtical);
        authorityInformationAccess.setAccessDescriptions(accessDescriptionList);
    }

    private void setCAIssuerUrls() {
        accessDescription.setAccessLocation(CA_ISSUER_URL);
        accessDescription.setAccessMethod(AccessMethod.CA_ISSUER);
        accessDescriptionList.add(accessDescription);
        authorityInformationAccess.setCritical(isCrtical);
        authorityInformationAccess.setAccessDescriptions(accessDescriptionList);
    }

    private ASN1EncodableVector addAccessDescriptionstoAIA(final AuthorityInformationAccess authorityInformationAccess) {
        final ASN1EncodableVector authorityInfoAccess = new ASN1EncodableVector();

        final List<AccessDescription> list = authorityInformationAccess.getAccessDescriptions();

        for (final AccessDescription accessDescription : list) {
            if (AccessMethod.CA_ISSUER == accessDescription.getAccessMethod()) {
                final org.bouncycastle.asn1.x509.AccessDescription caIssuers = new org.bouncycastle.asn1.x509.AccessDescription(org.bouncycastle.asn1.x509.AccessDescription.id_ad_caIssuers,
                        new GeneralName(GeneralName.uniformResourceIdentifier, new DERIA5String(accessDescription.getAccessLocation())));
                authorityInfoAccess.add(caIssuers);
            } else if (AccessMethod.OCSP == accessDescription.getAccessMethod()) {
                if (accessDescription.getAccessLocation() != null) {
                    final org.bouncycastle.asn1.x509.AccessDescription ocsp = new org.bouncycastle.asn1.x509.AccessDescription(org.bouncycastle.asn1.x509.AccessDescription.id_ad_ocsp,
                            new GeneralName(GeneralName.uniformResourceIdentifier, new DERIA5String(accessDescription.getAccessLocation())));
                    authorityInfoAccess.add(ocsp);
                }
            }
        }
        return authorityInfoAccess;
    }
}
