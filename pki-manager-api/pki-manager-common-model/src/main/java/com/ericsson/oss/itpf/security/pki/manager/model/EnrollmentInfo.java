/*------------------------------------------------------------------------------
 ********************************************************************************
 * COPYRIGHT Ericsson 2015
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 ********************************************************************************
 *----------------------------------------------------------------------------*/

package com.ericsson.oss.itpf.security.pki.manager.model;

import java.io.Serializable;
import java.security.cert.X509Certificate;

/**
 * This class holds the information required for node enrollment.
 * 
 */
public class EnrollmentInfo implements Serializable {

    private static final long serialVersionUID = -3457350520732961504L;
    private X509Certificate caCertificate;
    private String enrollmentURL;
    private String trustDistributionPointURL;
    private String ipv4EnrollmentURL;
    private String ipv6EnrollmentURL;

    /**
     * @return the caCertificate
     */
    public X509Certificate getCaCertificate() {
        return caCertificate;
    }

    /**
     * @param caCertificate
     *            the caCertificate to set
     */
    public void setCaCertificate(final X509Certificate caCertificate) {
        this.caCertificate = caCertificate;
    }

    /**
     * @return the enrollmentURL
     * 
     * @deprecated enrollmentURL parameter is deprecated due to the introduction of new parameters for the IPv4 and IPv6 enrollment urls.
     */
    @Deprecated
    public String getEnrollmentURL() {
        return enrollmentURL;
    }

    /**
     * @param enrollmentURL
     *            the enrollmentURL to set
     * 
     * @deprecated enrollmentURL parameter is deprecated due to the introduction of new parameters for the IPv4 and IPv6 enrollment urls.
     */
    @Deprecated
    public void setEnrollmentURL(final String enrollmentURL) {
        this.enrollmentURL = enrollmentURL;
    }

    /**
     * @return the trustDistributionPointURL
     * 
     * @deprecated trustDistributionPointURL parameter is deprecated because this variable is not used to get trustDistributionPointURL value. Instead of this variable
     *             getTrustDistributionPointUrl()/getTrustDistributionPointUrls() is used to return trustDistributionPointURL value.
     */
    @Deprecated
    public String getTrustDistributionPointURL() {
        return trustDistributionPointURL;
    }

    /**
     * @param trustDistributionPointURL
     *            the trustDistributionPointURL to set
     * 
     * @deprecated trustDistributionPointURL parameter is deprecated because this variable is not used to get trustDistributionPointURL value. Instead of this variable
     *             getTrustDistributionPointUrl()/getTrustDistributionPointUrls() is used to return trustDistributionPointURL value.
     */
    @Deprecated
    public void setTrustDistributionPointURL(final String trustDistributionPointURL) {
        this.trustDistributionPointURL = trustDistributionPointURL;
    }

    /**
     * @return the ipv4EnrollmentURL
     */
    public String getIpv4EnrollmentURL() {
        return ipv4EnrollmentURL;
    }

    /**
     * @param ipv4EnrollmentURL
     *            the ipv4EnrollmentURL to set
     */
    public void setIpv4EnrollmentURL(String ipv4EnrollmentURL) {
        this.ipv4EnrollmentURL = ipv4EnrollmentURL;
    }

    /**
     * @return the ipv6EnrollmentURL
     */
    public String getIpv6EnrollmentURL() {
        return ipv6EnrollmentURL;
    }

    /**
     * @param ipv6EnrollmentURL
     *            the ipv6EnrollmentURL to set
     */
    public void setIpv6EnrollmentURL(String ipv6EnrollmentURL) {
        this.ipv6EnrollmentURL = ipv6EnrollmentURL;
    }

    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Object#hashCode()
     */
    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((caCertificate == null) ? 0 : caCertificate.hashCode());
        result = prime * result + ((enrollmentURL == null) ? 0 : enrollmentURL.hashCode());
        result = prime * result + ((trustDistributionPointURL == null) ? 0 : trustDistributionPointURL.hashCode());
        result = prime * result + ((ipv4EnrollmentURL == null) ? 0 : ipv4EnrollmentURL.hashCode());
        result = prime * result + ((ipv6EnrollmentURL == null) ? 0 : ipv6EnrollmentURL.hashCode());
        return result;
    }

    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Object#equals(java.lang.Object)
     */
    @Override
    public boolean equals(final Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final EnrollmentInfo other = (EnrollmentInfo) obj;
        if (caCertificate == null) {
            if (other.caCertificate != null) {
                return false;
            }
        } else if (!caCertificate.equals(other.caCertificate)) {
            return false;
        }

        if (enrollmentURL == null) {
            if (other.enrollmentURL != null) {
                return false;
            }
        } else if (!enrollmentURL.equals(other.enrollmentURL)) {
            return false;
        }

        if (trustDistributionPointURL == null) {
            if (other.trustDistributionPointURL != null) {
                return false;
            }
        } else if (!trustDistributionPointURL.equals(other.trustDistributionPointURL)) {
            return false;
        }

        if (ipv4EnrollmentURL == null) {
            if (other.ipv4EnrollmentURL != null) {
                return false;
            }
        } else if (!ipv4EnrollmentURL.equals(other.ipv4EnrollmentURL)) {
            return false;
        }

        if (ipv6EnrollmentURL == null) {
            if (other.ipv6EnrollmentURL != null) {
                return false;
            }
        } else if (!ipv6EnrollmentURL.equals(other.ipv6EnrollmentURL)) {
            return false;
        }
        return true;
    }

    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
        return "EnrollmentInfo [" + ((null == caCertificate) ? "" : ("x509Certificate=" + caCertificate)) + ((null == enrollmentURL) ? "" : (", enrollmentURL=" + enrollmentURL))
                + ((null == trustDistributionPointURL) ? "" : (", trustDistributionPointURL=" + trustDistributionPointURL))
                + ((null == ipv4EnrollmentURL) ? "" : (", ipv4EnrollmentURL=" + ipv4EnrollmentURL)) + ((null == ipv6EnrollmentURL) ? "" : (", ipv6EnrollmentURL=" + ipv6EnrollmentURL)) + "]";
    }

}
