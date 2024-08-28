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
package com.ericsson.oss.itpf.security.pki.common.test.utilities;

import java.util.*;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;

import com.ericsson.oss.itpf.security.pki.common.test.constants.Constants;


public class EntityNameUtility {

    /**
     * Get CN (commonName) from DN (Distinguished Name)<br>
     * E.g.: if dn is <i>O=Ericsson,OU=ericssonOAM,<b>CN=skynetAICertCA</b></i>
     * then it will return skynetAICertCA About DN see <a
     * href="http://www.ietf.org/rfc/rfc2253.txt">RFC2253</a>
     * 
     * @param dn
     * @return CN or <code>null</code> if there is no CN in DN
     * @throws InvalidNameException
     */

    public static String getCNfromDN(final String domainName) throws InvalidNameException {
        final String neededAttributeType = Constants.COMMON_NAME;
        final LdapName ldapName = new LdapName(domainName);
        final List<Rdn> rdns = ldapName.getRdns();
        String commonName = null;
        for (final Rdn rdn : rdns) {
            if (rdn.getType().equalsIgnoreCase(neededAttributeType)) {
                commonName = (String) Rdn.unescapeValue(rdn.getValue().toString());
                break;
            }
        }
        return commonName;
    }

    public static boolean compareDNs(final String dn1, final String dn2) throws InvalidNameException {
        final LdapName ldn1 = new LdapName(dn1);
        final LdapName ldn2 = new LdapName(dn2);
        return compareLdapDNs(ldn1, ldn2);
    }

    private static boolean compareLdapDNs(final LdapName ldn1, final LdapName ldn2) {
        final List<Rdn> rdns1 = ldn1.getRdns();
        final List<Rdn> rdns2 = ldn2.getRdns();
        boolean isLdapDNEqual = false;
        if (rdns1.size() == rdns2.size()) {
            isLdapDNEqual = true;
            final Map<String, String> rdnMap2 = getRdnMap(ldn2);
            for (final Rdn rdn1 : rdns1) {
                final String rdn2 = rdnMap2.get(rdn1.getType().toLowerCase());
                final String rdn1String = getRdnValueString(rdn1);
                if (!rdn1String.equals(rdn2)) {
                    isLdapDNEqual = false;
                    break;
                }
            }
        }
        return isLdapDNEqual;
    }

    private static Map<String, String> getRdnMap(final LdapName ldn) {
        final Map<String, String> rdnMap = new HashMap<String, String>();
        for (final Rdn rdn : ldn.getRdns()) {
            rdnMap.put(rdn.getType().toLowerCase(), getRdnValueString(rdn));
        }
        return rdnMap;
    }

    private static String getRdnValueString(final Rdn rdn) {
        return (String) Rdn.unescapeValue(rdn.getValue().toString());
    }

}
