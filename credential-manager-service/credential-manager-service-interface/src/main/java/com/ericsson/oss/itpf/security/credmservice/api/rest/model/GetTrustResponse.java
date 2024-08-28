/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2020
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/

package com.ericsson.oss.itpf.security.credmservice.api.rest.model;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.util.HashMap;
import java.util.Map;

import javax.xml.bind.DatatypeConverter;
import javax.xml.bind.annotation.XmlRootElement;

import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerCertificateAuthority;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerTrustMaps;

@XmlRootElement
public class GetTrustResponse {

    private Map<String, String> intTrusts;
    private Map<String, String> extTrusts;

    public GetTrustResponse(final CredentialManagerTrustMaps trustMap) {
        super();
        intTrusts = new HashMap<>();
        extTrusts = new HashMap<>();

        putMapIntoTrusts(trustMap.getInternalCATrustMap(), intTrusts);

        putMapIntoTrusts(trustMap.getExternalCATrustMap(), extTrusts);
    }

    /**
     * @return the intTrusts
     */
    public Map<String, String> getIntTrusts() {
        return intTrusts;
    }

    /**
     * @param intTrusts
     *            the intTrusts to set
     */
    public void setIntTrusts(final Map<String, String> intTrusts) {
        this.intTrusts = intTrusts;
    }

    /**
     * @return the extTrusts
     */
    public Map<String, String> getExtTrusts() {
        return extTrusts;
    }

    /**
     * @param extTrusts
     *            the extTrusts to set
     */
    public void setExtTrusts(final Map<String, String> extTrusts) {
        this.extTrusts = extTrusts;
    }

    /**
     * @param intCa
     */
    private void putMapIntoTrusts(final Map<String, CredentialManagerCertificateAuthority> inputCa, final Map<String, String> inputTrust) {
        for (final Map.Entry<String, CredentialManagerCertificateAuthority> entry : inputCa.entrySet()) {
            final ByteArrayOutputStream bos = new ByteArrayOutputStream();
            ObjectOutput out = null;
            final CredentialManagerCertificateAuthority ca = entry.getValue();
            try {
                out = new ObjectOutputStream(bos);
                out.writeObject(ca);
            } catch (final IOException e) { // NOSONAR
                e.printStackTrace();
            }
            final byte[] caBytes = bos.toByteArray();
            inputTrust.put(entry.getKey(), new String(DatatypeConverter.printBase64Binary(caBytes)));
        }
    }

    public GetTrustResponse() {
        super();
    }

}
