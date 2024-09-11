package io.mosip.credentialstore.dto;

import java.io.Serializable;
import java.util.List;

import lombok.Data;

@Data
public class Source implements Serializable {

	private static final long serialVersionUID = 1L;

	public String attribute;

	public List<Filter> filter;
}
