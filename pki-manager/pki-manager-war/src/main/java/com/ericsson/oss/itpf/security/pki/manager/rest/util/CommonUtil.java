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
package com.ericsson.oss.itpf.security.pki.manager.rest.util;

import java.io.*;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.inject.Inject;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.StreamingOutput;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.*;
import org.json.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.CertificateExtension;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.KeyPurposeId;
import com.ericsson.oss.itpf.security.pki.common.model.crl.revocation.RevocationReason;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.eservice.PKIManagerEServiceProxy;
import com.ericsson.oss.itpf.security.pki.manager.common.enums.CertificateExtensionType;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.CertificateProfile;
import com.ericsson.oss.itpf.security.pki.manager.rest.dto.AttributeType;
import com.ericsson.oss.itpf.security.pki.manager.rest.dto.ErrorMessageDTO;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * A utility class that converts the error message to JSON string containing ID along with the error message.
 * 
 * @author xhemgan
 * @version 1.1.30
 * 
 */
public class CommonUtil {

    @Inject
    private LoadErrorProperties loadErrorProperties;

    @Inject
    private ObjectMapperUtil objectMapperUtil;

    @Inject
    private ErrorMessageDTO errorMessageDTO;

    @Inject
    private PKIManagerEServiceProxy pkiManagerEServiceProxy;

    private final static String INTERNA_SERVER_ERROR = "{\"code\":11001,\"message\":\"An unexpected internal system error occurred. Please check logs.\"}";

    private final static String CRLDISTRIBUTIONPOINT_OID = "2.5.29.31";

    private static final Logger LOGGER = LoggerFactory.getLogger(CommonUtil.class);
    /**
     * @param errorMessage
     *            The error message that should be converted to JSON
     * @return the JSON string containing given error message along with its ID
     * @throws IOException
     */
    public String getJSONErrorMessage(final String errorMessage) {

        final ObjectMapper mapper = objectMapperUtil.getObjectMapper(ObjectMapperType.ERROR_MESSAGE_MAPPER);
        String result;

        try {
            errorMessageDTO = loadErrorProperties.getErrorMessageDTO(errorMessage);

            result = mapper.writeValueAsString(errorMessageDTO);
        } catch (final Exception e) {
            LOGGER.debug("Illegal Arugment found ", e);
            return INTERNA_SERVER_ERROR;
        }
        return result;
    }

    /**
     * places the given attribute in the first row in the JSON array.
     * 
     * @param jsonArray
     *            JSON array which has to be sorted.
     * @param attributeType
     *            type of the attribute based on which the array has to be sorted.
     * @param attributeValue
     *            value of the attribute which has to be placed in the first row.
     * @return a sorted JSON array in String.
     * 
     */
    public String placeAttributeAtFirst(final JSONArray jsonArray, final AttributeType attributeType, final String attributeValue) {

        final JSONArray sortedArray = new JSONArray();

        for (int i = 0; i < jsonArray.length(); i++) {

            final JSONObject jsonObject = jsonArray.getJSONObject(i);

            if (jsonObject.get(attributeType.getValue()).toString().equals(attributeValue)) {
                jsonArray.remove(i);
                sortedArray.put(0, jsonObject);
            }
        }

        return mergeJsonArray(sortedArray, jsonArray).toString();
    }

    /**
     * places the given attribute in the first row in the JSON array.
     * 
     * @param jsonArray
     *            JSON array which has to be sorted.
     * @param attributeType
     *            type of the attribute based on which the array has to be sorted.
     * @param attributeValue
     *            value of the attribute which has to be placed in the first row.
     * @return a sorted JSON array in String.
     * 
     */
    public String placeAttributeAtFirstForEntities(final JSONArray jsonArray, final AttributeType attributeType, final String attributeValue) {

        final JSONArray sortedArray = new JSONArray();

        for (int i = 0; i < jsonArray.length(); i++) {

            final JSONObject jsonObject = jsonArray.getJSONObject(i);
            final String entityType = jsonObject.getString("type");
            final EntityType entityTypeEnum = EntityType.valueOf(entityType);

            if (entityTypeEnum == EntityType.CA_ENTITY) {
                if (jsonObject.getJSONObject("certificateAuthority").get(attributeType.getValue()).toString().equals(attributeValue)) {
                    jsonArray.remove(i);
                    sortedArray.put(0, jsonObject);
                }
            } else {
                if (jsonObject.getJSONObject("entityInfo").get(attributeType.getValue()).toString().equals(attributeValue)) {
                    jsonArray.remove(i);
                    sortedArray.put(0, jsonObject);
                }
            }
        }
        return mergeJsonArray(sortedArray, jsonArray).toString();
    }

    /**
     * merges the input JSON arrays into one.
     * 
     * @param jsonArrays
     *            one or more JSON arrays that should be merged.
     * @return the me merged JSON array.
     */
    public JSONArray mergeJsonArray(final JSONArray... jsonArrays) {

        final JSONArray mergedJsonArray = new JSONArray();

        for (final JSONArray jsonArray : jsonArrays) {
            for (int i = 0; i < jsonArray.length(); i++) {
                mergedJsonArray.put(jsonArray.getJSONObject(i));
            }
        }

        return mergedJsonArray;
    }

    /**
     * Returns {@link CertificateExtension} of given type from {@link CertificateProfile} of given id
     * 
     * @param id
     *            id of the {@link CertificateProfile} from which {@link CertificateExtension} should be fetched
     * @param certExtension
     *            type of the {@link CertificateExtension} that has to be retrieved
     * 
     * @return {@link CertificateExtension} type object
     */
    public <T extends CertificateExtension> T getCertificateExtension(final int id, final Class<T> certExtension) {

        CertificateProfile certificateProfile = new CertificateProfile();
        certificateProfile.setId(id);

        certificateProfile = pkiManagerEServiceProxy.getProfileManagementService().getProfile(certificateProfile);

        final List<CertificateExtension> certificateExtensions = certificateProfile.getCertificateExtensions().getCertificateExtensions();

        final CertificateExtensionType certificateExtensionTypeGiven = CertificateExtensionType.getCertificateExtensionType(certExtension.getSimpleName());

        for (final CertificateExtension certificateExtension : certificateExtensions) {

            final CertificateExtensionType certificateExtensionType = CertificateExtensionType.getCertificateExtensionType(certificateExtension.getClass().getSimpleName());

            if (certificateExtensionType.equals(certificateExtensionTypeGiven)) {
                return (T) certificateExtension;
            }
        }
        return null;
    }

    /**
     * Get the cRLDistributionPoints of certificate
     * 
     * @param x509Certificate
     * 
     * @return the cRLDistributionPoints list
     * 
     */
    public List<String> getCRLDistributionPoint(final X509Certificate x509Certificate) throws IOException {

        final byte[] cRLDistributionPoints = x509Certificate.getExtensionValue(CRLDISTRIBUTIONPOINT_OID);

        DEROctetString dosCrlDP = null;
        if (cRLDistributionPoints != null) {
            final ASN1InputStream oAsnInStream = new ASN1InputStream(new ByteArrayInputStream(cRLDistributionPoints));
            final ASN1Primitive derObjCrlDP = oAsnInStream.readObject();
            dosCrlDP = (DEROctetString) derObjCrlDP;
            oAsnInStream.close();
        }

        final List<String> crlUrls = new ArrayList<String>();
        if (dosCrlDP != null) {
            final byte[] crldpExtOctets = dosCrlDP.getOctets();
            CRLDistPoint distPoint = null;
            if (crldpExtOctets != null) {
                final ASN1InputStream oAsnInStream2 = new ASN1InputStream(new ByteArrayInputStream(crldpExtOctets));
                final ASN1Primitive derObj2 = oAsnInStream2.readObject();
                distPoint = CRLDistPoint.getInstance(derObj2);
                oAsnInStream2.close();
            }
            if(distPoint == null){
                return crlUrls;
            }
            for (final DistributionPoint dp : distPoint.getDistributionPoints()) {
                final DistributionPointName dpn = dp.getDistributionPoint();
                if (dpn != null) {
                    if (dpn.getType() == DistributionPointName.FULL_NAME) {
                        final GeneralName[] genNames = GeneralNames.getInstance(dpn.getName()).getNames();
                        for (int j = 0; j < genNames.length; j++) {
                            if (genNames[j].getTagNo() == GeneralName.uniformResourceIdentifier) {
                                final String url = DERIA5String.getInstance(genNames[j].getName()).getString();
                                crlUrls.add(url);
                            }
                        }
                    }
                }
            }
            return crlUrls;
        } else {
            return crlUrls;
        }
    }

    /**
     * Get the ExtendedKeyUsage of certificate
     * 
     * @param list
     *            of extendedKeyUsages
     * 
     * @return the {@link KeyPurposeId} list
     * 
     */
    public List<KeyPurposeId> getExtendedKeyUsage(final List<String> extendedKeyUsages) {
        List<KeyPurposeId> keyPurposeId = null;
        if (extendedKeyUsages != null && !extendedKeyUsages.isEmpty()) {
            keyPurposeId = new ArrayList<KeyPurposeId>();

            for (final String extendedKeyUsage : extendedKeyUsages) {
                keyPurposeId.add(KeyPurposeId.fromOid(extendedKeyUsage));
            }
        }
        return keyPurposeId;
    }

    /**
     * Get the RevocationInfoDTO by parsing the given JSON String w.r.to the Class of type T.
     * 
     * @param clazz
     *            Class of type T w.r.to which the JSON String need to parse.
     * @param jsonString
     *            JSON String.
     * @return object of type T.
     * @throws IOException
     *             is thrown when error occurs while processing the JSON String.
     */
    public <T extends Object> T getRevocationInfoDTO(final Class<T> clazz, final String jsonString) throws IOException {
        final ObjectMapper mapper = objectMapperUtil.getObjectMapper(ObjectMapperType.REVOCATION_REASON_DESERIALIZER_MAPPER);
        final T object = mapper.reader(clazz).readValue(jsonString);
        return object;
    }

    /**
     * Produce JSON Response with the given list of class objects
     * 
     * @param objectList
     *            List of objects of type T.
     * @return {@link Response}
     * @throws JsonProcessingException
     *             is thrown when error occurs while processing the JSON String.
     */
    public <T extends Object> Response produceJsonResponse(final List<T> objectList) throws JsonProcessingException {
        final ObjectMapper mapper = objectMapperUtil.getObjectMapper(ObjectMapperType.COMMON_MAPPER);
        return Response.status(207).entity(mapper.writeValueAsString(objectList)).build();
    }

    /**
     * Get the list of RevocationInfoDTO from the given JSON array w.r.to the Class of type T.
     * 
     * @param clazz
     *            Class of type T w.r.to which the JSON array String need to parse.
     * @param jsonArrayString
     *            JSON array in String format.
     * @return List of objects of type T.
     * @throws IOException
     *             is thrown when error occurs while processing the JSON String.
     * @throws JSONException
     *             is thrown when error occurs while converting String to JSON array.
     */
    public <T extends Object> List<T> getRevocationInfoDTOList(final Class<T> clazz, final String jsonArrayString) throws IOException, JSONException {
        final List<T> revocationInfoDTOList = new ArrayList<T>();
        final JSONArray jsonArray = new JSONArray(jsonArrayString);

        for (int index = 0; index < jsonArray.length(); index++) {
            final String jsonString = jsonArray.getJSONObject(index).toString();
            final T obj = getRevocationInfoDTO(clazz, jsonString);
            revocationInfoDTOList.add(obj);
        }
        return revocationInfoDTOList;
    }

    /**
     * Produce JSONString containing all revocationReasons.
     * 
     * @return String
     * @throws JsonProcessingException
     *             is thrown when error occurs while processing the JSON String.
     */
    public String getRevocationReasons() throws JsonProcessingException {
        final ObjectMapper mapper = objectMapperUtil.getObjectMapper(ObjectMapperType.REVOCATION_REASON_MAPPER);

        return mapper.writeValueAsString(RevocationReason.values());

    }

    /**
     * Get the StreamingOutput from a file
     * 
     * @param file
     *            input file from which StreamingOutput will be taken.
     * @return StreamingOutput
     * 
     * @throws FileNotFoundException
     *             thrown when failed to get the FileOutputStream from the input file.
     * @throws IOException
     *             thrown when failed to write the outputStream from the file.
     */
    public StreamingOutput getStreamingOutput(final File file) throws FileNotFoundException {
        final InputStream responseStream = new FileInputStream(file);
        final StreamingOutput streamingOutput = new StreamingOutput() {
            @Override
            public void write(final OutputStream out) throws IOException {
                int length;
                byte[] buffer = new byte[1024];
                try {
                    while ((length = responseStream.read(buffer)) != -1) {
                        out.write(buffer, 0, length);
                    }
                    out.flush();
                } finally {
                    responseStream.close();
                }
            }

        };

        return streamingOutput;
    }
}
