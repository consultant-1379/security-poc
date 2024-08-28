/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2019
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/

package com.ericsson.oss.services.cm.admin.utility;

import java.nio.charset.StandardCharsets;

import javax.inject.Inject;
import javax.xml.bind.DatatypeConverter;

import com.ericsson.oss.itpf.security.cryptography.CryptographyService;

public class PasswordHelper {

    @Inject
    private CryptographyService cryptographyService;

    /**
     * Encrypt and encode the String text.
     *
     * @param text
     *            String to be encoded.
     * @return String
     */
    public String encryptEncode(final String text) {
        if (text == null) {
            return null;
        }
        return encode(encrypt(text));
    }

    /**
     * Decrypt and decode the String text.
     *
     * @param text
     *            String to be decoded.
     * @return String
     */
    public String decryptDecode(final String text) {
        return decrypt(decode(text));
    }

    private String encode(final byte[] bytes) {
        return DatatypeConverter.printBase64Binary(bytes);
    }

    private byte[] encrypt(final String text) {
        return cryptographyService.encrypt(text.getBytes(StandardCharsets.UTF_8));
    }

    private byte[] decode(final String value) {
        return DatatypeConverter.parseBase64Binary(value);
    }

    private String decrypt(final byte[] encryptedBytes) {
        return new String(cryptographyService.decrypt(encryptedBytes));
    }

}

