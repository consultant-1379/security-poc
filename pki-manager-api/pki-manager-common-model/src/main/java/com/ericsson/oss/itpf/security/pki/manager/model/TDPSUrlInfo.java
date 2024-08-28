/*------------------------------------------------------------------------------
 ********************************************************************************
 * COPYRIGHT Ericsson 2016
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

/**
 * This class holds the information required for TrustDistributionPointService IPv4 and IPv6 addresses.
 * 
 * @author xchowja
 */
public class TDPSUrlInfo implements Serializable {

    private static final long serialVersionUID = -4416823721072128053L;
    private String ipv4Address;
    private String ipv6Address;

    /**
     * @return the ipv4Address
     */
    public String getIpv4Address() {
        return ipv4Address;
    }

    /**
     * @param ipv4Address
     *            the ipv4Address to set
     */
    public void setIpv4Address(final String ipv4Address) {
        this.ipv4Address = ipv4Address;
    }

    /**
     * @return the ipv6Address
     */
    public String getIpv6Address() {
        return ipv6Address;
    }

    /**
     * @param ipv6Address
     *            the ipv6Address to set
     */
    public void setIpv6Address(final String ipv6Address) {
        this.ipv6Address = ipv6Address;
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
        result = prime * result + ((ipv4Address == null) ? 0 : ipv4Address.hashCode());
        result = prime * result + ((ipv6Address == null) ? 0 : ipv6Address.hashCode());
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
        final TDPSUrlInfo other = (TDPSUrlInfo) obj;
        if (ipv4Address == null) {
            if (other.ipv4Address != null) {
                return false;
            }
        } else if (!ipv4Address.equals(other.ipv4Address)) {
            return false;
        }
        if (ipv6Address == null) {
            if (other.ipv6Address != null) {
                return false;
            }
        } else if (!ipv6Address.equals(other.ipv6Address)) {
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
        return "TDPSUrlInfo [ipv4Address=" + ipv4Address + ", ipv6Address=" + ipv6Address + "]";
    }
}
