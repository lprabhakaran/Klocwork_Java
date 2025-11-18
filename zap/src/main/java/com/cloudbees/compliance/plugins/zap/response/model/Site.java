package com.cloudbees.compliance.plugins.zap.response.model;

import java.util.ArrayList;

import com.google.gson.annotations.SerializedName;

import lombok.Data;
import lombok.ToString;

@Data
@ToString
public class Site {
	@SerializedName("@name")
	private String name;
	@SerializedName("@host")
	private String host;
	@SerializedName("@port")
	private String port;
	@SerializedName("@ssl")
	private String ssl;
	private ArrayList<ZapAlert> alerts;
}