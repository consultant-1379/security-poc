package com.ericsson.oss.services.scriptengine.rest.resources;

import javax.validation.constraints.NotNull;
import com.ericsson.oss.services.scriptengine.spi.dtos.AbstractDto;
import com.ericsson.oss.services.scriptengine.spi.dtos.ResponseDto;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

public class GetResponseBody {
    private final List<AbstractDto> nonCachableDtos;
    private final ResponseDto responseDto;

    public GetResponseBody(@JsonProperty("nonCachableDtos") @NotNull final List<AbstractDto> nonCachableDtos,@JsonProperty("responseDtos") @NotNull final ResponseDto responseDto) {
        this.nonCachableDtos = nonCachableDtos;
        this.responseDto = responseDto;
    }

    public ResponseDto getResponseDto() {
        return responseDto;
    }

    public List<AbstractDto> getNonCachableDtos() {
        return nonCachableDtos;
    }

    @Override
    public boolean equals(final Object o) {
        if (this == o){
            return true;
        }
        if (o == null || getClass() != o.getClass()){
            return false;
        }

        final GetResponseBody that = (GetResponseBody) o;

        if (!nonCachableDtos.equals(that.nonCachableDtos)){
            return false;
        }
        return responseDto.equals(that.responseDto);
    }

    @Override
    public int hashCode() {
        int result = nonCachableDtos.hashCode();
        result = 31 * result + responseDto.hashCode();
        return result;
    }
}
