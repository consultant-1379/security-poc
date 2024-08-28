/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2012
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.credentialmanager.cli.model.utils;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Properties;

import com.ericsson.oss.itpf.security.credentialmanager.cli.exception.CredentialManagerException;
import com.ericsson.oss.itpf.security.credentialmanager.cli.util.Logger;
import com.ericsson.oss.itpf.security.credentialmanager.cli.util.PropertiesReader;

public class HostnameResolveUtil {

    final private Properties props;
    final private String fakeSubDN;
    final private String delimiter;

    public HostnameResolveUtil() {
        this.props = PropertiesReader.getConfigProperties();
        this.fakeSubDN = this.props.getProperty("subDName", "hostname");
        this.delimiter = this.props.getProperty("delimiter", "##");
    }

    // TORF-562254 update log4j
    private static final org.apache.logging.log4j.Logger LOG = Logger.getLogger();


    public String checkHostName(String paramToCheck) throws CredentialManagerException {

        String host = "";

        this.validateString(paramToCheck);

        final String toBeSobstituted = this.delimiter + this.fakeSubDN.toUpperCase() + this.delimiter;

        if (paramToCheck.toUpperCase().contains(toBeSobstituted)) {
            try {
                host = InetAddress.getLocalHost().getHostName();
            } catch (UnknownHostException e) {
                LOG.error("Checking host name {} [Failed]", paramToCheck);
            }

            LOG.debug(" The real hostname is = {} ", host);

            if (host != "" && host != null) {
                paramToCheck = paramToCheck.toUpperCase().replaceAll((this.delimiter + this.fakeSubDN.toUpperCase() + this.delimiter), host);
            } else {
                throw new CredentialManagerException(" Impossible to retreive proper hostname ");
            }
        }

        return paramToCheck;
    }

    public void validateString(final String stringToValidate) {

        /*
         * is supposed that only one substitution have to be applied inside the passed Subject DN
         */

        final int occurrences = this.delimiterCounter(stringToValidate);
        final String genericHostName = this.delimiter + this.fakeSubDN.toUpperCase() + this.delimiter;

        //case 1) occurrences of delimiter differ by 2 and > 0

        if (occurrences > 0 && occurrences != 2) {
            LOG.error(" Malformed SubjectDN in xml file, correct delimiter is {} correct fake hostname is {} ", delimiter, fakeSubDN);
            throw new CredentialManagerException(" Malformed SubjectDN in xml file, correct delimiter is  " + this.delimiter + " correct fake hostname is " + this.fakeSubDN);
        }

        //case 2) 2 occurrences of delimiter and well formed 'generic hostname' tag
        //case 3) 2 occurrences of delimiter but malformed tag (based on string length)
        if (occurrences == 2) {

            final int firstIndex = stringToValidate.indexOf(this.delimiter);
            final int lastIndex = stringToValidate.lastIndexOf(this.delimiter);

            if (firstIndex > 0 && lastIndex > 0) {
                final String substitution = stringToValidate.substring(firstIndex, lastIndex + 2);

                //malformed 'generic hostname' tag (based on string length)
                if (substitution.length() != genericHostName.length()) {

                    LOG.error("Malformed SubjectDN in xml file, based on string length");
                    throw new CredentialManagerException(" Malformed SubjectDN in xml file, correct delimiter is  " + this.delimiter + " correct fake hostname is " + this.fakeSubDN);

                    //well formed 'generic hostname' tag
                } else if (stringToValidate.toUpperCase().contains(genericHostName) || genericHostName.equalsIgnoreCase(substitution)) {
                    return;
                } else {

                    LOG.error("Malformed SubjectDN in xml file");
                    throw new CredentialManagerException(" Malformed SubjectDN in xml file, correct delimiter is  " + this.delimiter + " correct fake hostname is " + this.fakeSubDN);
                }
            }
        }

        //ToDo
        //case 4) no occurrences, may be good or, may be wrong in case of presence of 'hostname' without delimiters in xml file
    }

    private int delimiterCounter(final String text) {
        int n = 0;
        for (int i = 0; i <= text.length() - this.delimiter.length(); i++) {
            final String str = text.substring(i, i + this.delimiter.length());
            if (str.equals(this.delimiter)) {
                n++;
            }
        }
        return n;
    }

}
