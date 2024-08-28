/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2016
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/

package com.ericsson.oss.itpf.security.kaps.common;

/**
 * Class that defined all error messages from the validations performed.
 */
public class ErrorMessages {

    public static final String KEY_GENERATION_ALGORITHM_IS_NOT_SUPPORTED = "Provided Key generation algorithm is not supported.";
    public static final String UNABLE_TO_ENCRYPT = "Unable to encrypt the private key ";
    public static final String UNABLE_TO_DECRYPT = "Unable to decrypt the private key ";
    public static final String UNABLE_TO_GENERATE_KEYPAIR = "Unable to generate Key pair. ";
    public static final String UNABLE_TO_FETCH_KEYPAIR = "Unable to fetch the Key pair from store. ";
    public static final String UNABLE_TO_BUILD_PUBLICKEY = "Unable to bulid public key";
    public static final String UNABLE_TO_BUILD_PRIVATEKEY = "Unable to bulid private key";

    public static final String UNABLE_TO_SIGN_CRL = "Unable to sign the CRL with the given KeyPair and Signature Algorithm";
    public static final String UNABLE_TO_GET_SECRETKEY = "Unable to get the Secret Key ";
    public static final String UNABLE_TO_REMOVE_UNUSED_SECRETKEY = "Unable to remove un used Secret Key from DB ";
    public static final String UNABLE_GENERATE_SECRET_KEY = "Unable to generate master key";
    public static final String KEYIDENTIFIER_NOT_FOUND = "KeyIdentifier not found";
    public static final String UNABLE_TO_UPDATE_KEYIDENTIFIER = "Unable to upadate KeyIdentifierData";

    public static final String EXTENSION_ENCODING_IS_INVALID = "Extension encoding not proper. ";
    public static final String X509CERTIFICATE_GENERATION_FAILED = "Can not get the X509Certificate from X509CertificateBuilder.";

    public static final String CSR_SIGNATURE_GENERATION_FAILED = "CSR signature generation failed.";
    public static final String NO_SUCH_AlGORITHM = "Algorithm provided is not valid ";
    public static final String INVALID_CSR_ENCODING = "CSR encoding is not valid or not in correct format.";
    public static final String INVALID_CSR_EXTENSION = "Error while creating or adding CRL Extensions.";
    public static final String INVALID_KEY_IN_CSR = "Keys provided in the CSR are not valid. ";
    public static final String UNSUPPORTED_KEYPAIR_STATUS_OPERATION = "Can not change the Key pair status from InActive to Active.";

    public static final String CERTIFICATE_SIGNATURE_GENERATION_FAILED = "Certificate signature generation failed. ";
    public static final String CRL_SIGNATURE_GENERATION_FAILED = "CRL signature generation failed. ";
    public static final String SIGNATURE_GENERATION_FAILED = "Signature generation failed. ";
    public static final String UNABLE_TO_SAVE_PRAVATE_KEY = "Unable to save private key. ";
}
