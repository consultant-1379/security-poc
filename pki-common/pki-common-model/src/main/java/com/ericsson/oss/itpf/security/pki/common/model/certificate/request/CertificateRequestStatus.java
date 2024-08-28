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
package com.ericsson.oss.itpf.security.pki.common.model.certificate.request;

/**
 * Represents Certificate request status.
 * <ul>
 * <li>New : When the status is newly arrived and waiting to be issued.</li>
 * <li>Issued: When the certificate is successfully issued for that request.</li>
 * <li>Failed: When the certificate is failed to issued.</li>
 * </ul>
 * 
 */
public enum CertificateRequestStatus {
    NEW("new", 1), ISSUED("issued", 2), FAILED("failed", 3);
    private int id;

    public int getId() {
        return this.id;
    }

    private String certificateRequestStatus;

    CertificateRequestStatus(final String status, final int id) {
        certificateRequestStatus = status;
        this.id = id;
    }

    public String value() {
        return certificateRequestStatus;
    }

    public static CertificateRequestStatus fromValue(final String v) {
        return valueOf(v);
    }

    public static CertificateRequestStatus getStatus(final Integer id) {

        if (id == null) {
            return null;
        }

        for (final CertificateRequestStatus certificateRequestStatus : CertificateRequestStatus.values()) {
            if (id.equals(certificateRequestStatus.getId())) {
                return certificateRequestStatus;
            }
        }

        throw new IllegalArgumentException("No matching type for id " + id);
    }

    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Enum#toString()
     */
    @Override
    public String toString() {
        return super.toString();
    }

}
