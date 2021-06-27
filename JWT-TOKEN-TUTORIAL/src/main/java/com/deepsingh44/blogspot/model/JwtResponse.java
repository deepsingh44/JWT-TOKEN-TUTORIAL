package com.deepsingh44.blogspot.model;

public class JwtResponse {
	private final String jwttoken;

	public JwtResponse(String jwttoken) {
		this.jwttoken = jwttoken;
	}

	public String getJwttoken() {
		return jwttoken;
	}

}
