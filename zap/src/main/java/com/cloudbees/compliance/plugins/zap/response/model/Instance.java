package com.cloudbees.compliance.plugins.zap.response.model;

import lombok.Data;
import lombok.ToString;
@Data
@ToString
public class Instance{
    public String uri;
    public String method;
    public String param;
    public String attack;
    public String evidence;
}