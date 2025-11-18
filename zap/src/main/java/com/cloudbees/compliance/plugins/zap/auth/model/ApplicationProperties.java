package com.cloudbees.compliance.plugins.zap.auth.model;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.ArrayList;
import java.util.List;

@Configuration
@ConfigurationProperties(prefix = "manifest")
@EnableConfigurationProperties
public class ApplicationProperties {
    private String uuid;
    private String name;
    private String version;
    private List<AssetRole> assetRoles = new ArrayList<>();

    public String getUuid() {
        return uuid;
    }

    public void setUuid(String uuid) {
        this.uuid = uuid;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    public List<AssetRole> getAssetRoles() {
        return assetRoles;
    }

    public void setAssetRoles(List<AssetRole> assetRoles) {
        this.assetRoles = assetRoles;
    }

    public static class AssetRole {
        private String role;
        private String assetType;
        private Boolean requiresAssets;
        private Boolean createsAttributes;
        private Boolean createsBinaryAttributes;
        private String createSubAttributes;

		public String getRole() {
            return role;
        }

        public void setRole(String role) {
            this.role = role;
        }

        public String getAssetType() {
            return assetType;
        }

        public void setAssetType(String assetType) {
            this.assetType = assetType;
        }

        public Boolean getRequiresAssets() {
            return requiresAssets;
        }

        public void setRequiresAssets(Boolean requiresAssets) {
            this.requiresAssets = requiresAssets;
        }

        public Boolean getCreatesAttributes() {
			return createsAttributes;
		}

		public void setCreatesAttributes(Boolean createsAttributes) {
			this.createsAttributes = createsAttributes;
		}

		public Boolean getCreatesBinaryAttributes() {
			return createsBinaryAttributes;
		}

		public void setCreatesBinaryAttributes(Boolean createsBinaryAttributes) {
			this.createsBinaryAttributes = createsBinaryAttributes;
		}

		public String getCreateSubAttributes() {
			return createSubAttributes;
		}

		public void setCreateSubAttributes(String createSubAttributes) {
			this.createSubAttributes = createSubAttributes;
		}
    }
}
