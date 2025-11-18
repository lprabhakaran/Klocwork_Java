package com.cloudbees.compliance.plugins.zap.response.model;

import java.util.ArrayList;

import com.google.gson.annotations.SerializedName;

import lombok.Data;
import lombok.ToString;
@Data
@ToString
public class ZapResponse{
	
    @SerializedName("@version") 
    private String version;
    @SerializedName("@generated") 
    private String generated;
    @SerializedName("site") 
    private ArrayList<Site> sites;
}