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

package com.ericsson.oss.itpf.security.pki.core.certificatemanagement.generator;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Calendar;
import java.util.Random;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.core.common.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.CertificateGenerationException;

/**
 * Generates serial number for the certificate.
 */
public class SerialNumberGenerator {

    @Inject
    Logger logger;

    private static final String IPADDRESSDELIMITER = "\\.";

    /**
     * Generates the serial number for the certificate.
     *
     * @return Serial number generated for the certificate.
     * @throws CertificateGenerationException
     *             To indicate that an exception has occured during certificate generation
     */
    public String generateSerialNumber() throws CertificateGenerationException {

        final Random random = new Random();
        long randomResult = random.nextLong();
        randomResult = randomResult / 100;
        if (randomResult < 0) {
            randomResult = randomResult * -1;
        }
        InetAddress ip = null;
        try {
            ip = InetAddress.getLocalHost();
        } catch (final UnknownHostException e) {
            logger.debug(ErrorMessages.ERROR_GENERATING_SERIAL_NUMBER, e);
            throw new CertificateGenerationException(ErrorMessages.ERROR_GENERATING_SERIAL_NUMBER);
        }
        final String hostAddress = ip.getHostAddress();
        final int minutes = Calendar.getInstance().get(Calendar.MINUTE);
        final String[] octets = hostAddress.split(IPADDRESSDELIMITER);
        int getLastOctet = getLastOctet(octets);
        getLastOctet = getLastOctet + minutes;
        randomResult = randomResult * 100 + getLastOctet;
        return String.valueOf(randomResult);
    }

    private int getLastOctet(final String[] octets) {

        if (octets.length != 4) {
            return 0;
        }
        int val = -1;
        try {
            val = Integer.parseInt(octets[3]);
            if (val < 0 || val > 255) {
                return 0;
            }

        } catch (final NumberFormatException ex) {
            return 0;
        }
        if (octets[3].length() > 2) {
            return val % 100;
        }
        return val;
    }

}
