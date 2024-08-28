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
package com.ericsson.oss.services.cm.admin.rest.client.common;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.function.Function;

import com.fasterxml.jackson.core.type.TypeReference;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.http.util.EntityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Representation of REST response
 *
 * @param <T>
 *            Type of success data
 * @param <E>
 *            Type of error data
 */
public class RestResponse<T, E> {
    private static final Logger logger = LoggerFactory.getLogger(RestResponse.class);

    private static final ObjectMapper mapper = new ObjectMapper();
    private final int statusCode;
    private T data;
    private E errorDetails;

    /**
     * Construct {@link RestResponse} from {@link HttpResponse}
     *
     * @param response
     *            http response
     */

    public RestResponse(final HttpResponse response) {
        this.statusCode = response.getStatusLine().getStatusCode();
        this.data = null;
        this.errorDetails = null;

    }

    /**
     * Construct {@link RestResponse} from status code
     *
     * @param statusCode
     *            Status code value
     */

    public RestResponse(final int statusCode) {
        this.statusCode = statusCode;
        this.data = null;
        this.errorDetails = null;

    }

    /**
     * * Set success data on {@link RestResponse} object
     *
     * @param data
     *            Data to set on {@link RestResponse} object
     * @return {@link RestResponse} object
     */
    public RestResponse<T, E> setData(final T data) {
        this.data = data;
        return this;

    }

    /**
     * Set failure data on {@link RestResponse} object
     *
     * @param errorDetails
     *            Data to set on {@link RestResponse} object
     * @return {@link RestResponse} object
     */

    public RestResponse<T, E> setErrorDetails(final E errorDetails) {
        this.errorDetails = errorDetails;
        return this;

    }

    /**
     * Return status of {@link RestResponse}
     *
     * @return {@code true} if valid or {@code false} if not valid
     */

    public Boolean isValid() {
        return statusCode >= 200 && statusCode < 300;

    }

    /**
     * Get optional of success data from {@link RestResponse}
     *
     * @return Optional of success data
     */

    public Optional<T> getData() {
        return Optional.ofNullable(data);

    }

    /**
     * Get optional of failure data from {@link RestResponse}
     *
     * @return Optional of failure data
     */

    public Optional<E> getErrorDetails() {
        return Optional.ofNullable(errorDetails);

    }

    /**
     * Executes success consumer when REST response is valid
     *
     * @param success
     *            Consumer to execute; Lambda which takes {@link Optional} of success data type
     * @return {@link RestResponse} object
     */

    public RestResponse<T, E> ifSuccess(final Consumer<Optional<T>> success) {
        Objects.requireNonNull(success);
        if (isValid()) {
            success.accept(this.getData());
        }
        return this;

    }

    /**
     * Executes success consumer when REST response is valid
     *
     * @param success
     *            Consumer to execute; Lambda which takes {@link Integer} value as status code and {@link Optional} of success data type
     * @return {@link RestResponse} object
     */

    public RestResponse<T, E> ifSuccess(final BiConsumer<Integer, Optional<T>> success) {
        Objects.requireNonNull(success);
        if (isValid()) {
            success.accept(this.statusCode, this.getData());

        }
        return this;

    }

    /**
     * Executes failure consumer when REST response is valid
     *
     * @param failure
     *            Consumer to execute; Lambda which takes {@link Optional} of failure data type
     * @return {@link RestResponse} object
     */

    public RestResponse<T, E> ifFailure(final Consumer<Optional<E>> failure) {
        Objects.requireNonNull(failure);
        if (!isValid()) {
            failure.accept(this.getErrorDetails());
        }
        return this;

    }

    /**
     * Executes failure consumer when REST response is valid
     *
     * @param failure
     *            Consumer to execute; Lambda which takes {@link Integer} value as status code and {@link Optional} of failure data type
     * @return {@link RestResponse} object
     */
    public RestResponse<T, E> ifFailure(final BiConsumer<Integer, Optional<E>> failure) {
        Objects.requireNonNull(failure);
        if (!isValid()) {
            failure.accept(this.statusCode, this.getErrorDetails());

        }
        return this;

    }

    /**
     * Creates default response handler function. This handler deserialize JSON data to success type {@code T} in case of success response or to
     * failure type {@code E} in case of failure response
     *
     * @param entityType
     *            Success data class
     * @param errorDetailsType
     *            Failure data (error data) class
     * @param <T>
     *            Success data type
     * @param <E>
     *            Failure data (error data) type
     * @return object
     */

    public static <T, E> Function<HttpResponse, RestResponse<T, E>> getDefaultResponseHandler(final Class<T> entityType,
                                                                                              final Class<E> errorDetailsType) {
        return response -> {
            final int statusCode = response.getStatusLine().getStatusCode();
            final RestResponse<T, E> restResponse = new RestResponse<>(statusCode);
            if (restResponse.isValid()) {
                extractEntity(response, entityType).ifPresent(restResponse::setData);
            } else {
                extractEntity(response, errorDetailsType).ifPresent(restResponse::setErrorDetails);

            }
            return restResponse;
        };

    }

    /**
     * Extract/deserialize entity from JSON to {@code R} type
     *
     * @param response
     *            {@link HttpResponse} object
     * @param entityType
     *            Class of entity
     * @param <R>
     *            Type of entity
     * @return {@link Optional} of {@code R} * type
     */

    private static <R> Optional<R> extractEntity(final HttpResponse response, final Class<R> entityType) {
        try {
            HttpEntity httpEntity = response.getEntity();
            if (httpEntity != null) {
                if(entityType.isAssignableFrom(String.class))
                {
                    return (Optional<R>) Optional.ofNullable(EntityUtils.toString(httpEntity));
                }
                else
                {
                    final InputStream contentStream = httpEntity.getContent();
                    return Optional.ofNullable(mapper.readValue(contentStream, entityType));
                }
            } else {
                return Optional.empty();
            }
        } catch (IOException e) {
            return Optional.empty();
        }
    }

    /**
     * Extract/deserialize entity from JSON to given entity type
     *
     * @param response
     *            {@link HttpResponse} object
     * @param entityType
     *            Class of entity
     * @return {@link Optional} of given entity type
     */
    private static <T> Optional<List<T>> extractEntity(final HttpResponse response, TypeReference<List<T>> entityType) {
        try {
            final String content = EntityUtils.toString(response.getEntity());
            return Optional.ofNullable(mapper.readValue(content, entityType));
        } catch (IOException e) {
            logger.error(String.format("Error in conversion to entity type:%s", entityType.getType().getTypeName()), e);
            return Optional.empty();
        }
    }

    /**
     * Creates default response handler function. This handler de-serialize JSON data to given entity type
     * in case of success response or to given failure type in case of failure response
     *
     * @param entityType
     *            Success data class
     * @param errorDetailsType
     *            Failure data (error data) class
     * @return object
     */
    public static <T, E> Function<HttpResponse, RestResponse<List<T>, E>> getDefaultResponseHandler(TypeReference<List<T>> entityType,
                                                                                                    final Class<E> errorDetailsType) {
        return response -> {
            final int statusCode = response.getStatusLine().getStatusCode();
            final RestResponse<List<T>, E> restResponse = new RestResponse<>(statusCode);
            if (restResponse.isValid()) {
                extractEntity(response, entityType).ifPresent(restResponse::setData);
            } else {
                extractEntity(response, errorDetailsType).ifPresent(restResponse::setErrorDetails);
            }
            return restResponse;
        };
    }
}
