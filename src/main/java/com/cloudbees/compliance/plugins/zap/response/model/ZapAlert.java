package com.cloudbees.compliance.plugins.zap.response.model;

import java.util.ArrayList;

import lombok.Data;
import lombok.ToString;

@Data
@ToString
public class ZapAlert {

	private String pluginId;
	private String alertRef;
	private String alert;
	private String name;
	private String riskcode;
	private String confidence;
	private String riskdesc;
	private String desc;
	private ArrayList<Instance> instances;
	private String count;
	private String solution;
	private String otherinfo;
	private String reference;
	private String cweid;
	private String wascid;
	private String sourceid;

}
