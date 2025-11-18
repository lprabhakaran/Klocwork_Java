package com.cloudbees.compliance.plugins.zap.util;

import static com.cloudbees.compliance.plugins.zap.constant.ZapApiConstants.CWEID_CODE_PREFIX;
import static com.cloudbees.compliance.plugins.zap.constant.ZapAuthConstants.APP_AUTH_FAILURE_MESSAGE;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import org.apache.commons.lang3.ObjectUtils;
import org.jsoup.Jsoup;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.ConfigurableBeanFactory;
import org.springframework.context.annotation.Scope;
import org.springframework.stereotype.Component;

import com.cloudbees.compliance.plugins.findings.utils.DisplayUtil;
import com.cloudbees.compliance.plugins.findings.utils.TrackingUtil;
import com.cloudbees.compliance.plugins.grpc.model.Category;
import com.cloudbees.compliance.plugins.zap.constant.ZapApiConstants;
import com.cloudbees.compliance.plugins.zap.response.model.Instance;
import com.cloudbees.compliance.plugins.zap.response.model.Site;
import com.cloudbees.compliance.plugins.zap.response.model.ZapAlert;
import com.cloudbees.compliance.plugins.zap.response.model.ZapResponse;
import com.cloudbees.compliance.plugins.zap.service.ZapReportService;
import com.cloudbees.compliance.service.v040.Asset;
import com.cloudbees.compliance.service.v040.AssetProfile;
import com.cloudbees.compliance.service.v040.AssetProfileFinding;
import com.cloudbees.compliance.service.v040.AssetResult;
import com.cloudbees.compliance.service.v040.DetailRow;
import com.cloudbees.compliance.service.v040.EvalFindings;
import com.cloudbees.compliance.service.v040.Evaluation;
import com.google.gson.Gson;
import com.google.protobuf.ByteString;

@Component
@Scope(ConfigurableBeanFactory.SCOPE_PROTOTYPE)
public class ZapEvaluationUtils {

	private static final Logger LOGGER = LoggerFactory.getLogger(ZapEvaluationUtils.class);

	@Autowired
	private DisplayUtil displayUtil;

	@Autowired
	private TrackingUtil trackingUtil;
	
	@Autowired
	private ZapReportService zapReportServiceImpl;
	
	public List<Evaluation> generateEvaluations(Asset asset, AssetProfile assetProfile, ZapResponse zapResponse,
			List<String> includedContexts,String contextName) throws IOException {

		LOGGER.info("In generateEvaluations()");

		if(zapResponse == null) {
			LOGGER.debug("zap response is null");
			return new ArrayList<>();
		}
		List<Evaluation> evaluationList = new ArrayList<>();
		ArrayList<Site> sites = zapResponse.getSites();
		ArrayList<ZapAlert> mergedSitesAlert = new ArrayList<>();

		getAlerts(includedContexts, sites, mergedSitesAlert);
		var retry=0;
		while (mergedSitesAlert.isEmpty() && retry <= ZapApiConstants.RETRY_COUNT) {			
             retry++;
             sleepDuringRetries( retry,  ZapApiConstants.RETRY_COUNT);
			 zapResponse = zapReportServiceImpl.generateReport(contextName);
			 sites = zapResponse.getSites();
			 mergedSitesAlert = new ArrayList<>();
			 getAlerts(includedContexts, sites, mergedSitesAlert);			
		}

		Map<String, List<ZapAlert>> map = mergedSitesAlert.stream()
				.collect(Collectors.groupingBy(ZapAlert::getCweid, Collectors.toList()));

		String importance = "";
		String decription = "";
		String code = "";
		String name = "";
		
		String remediation;
		
		for (Entry<String, List<ZapAlert>> entrySet : map.entrySet()) {

			ZapAlert highestSeverityAlert = new ZapAlert();
			// cwe id like CWE-345
			code = CWEID_CODE_PREFIX + entrySet.getKey();

			// find the max alert by riskCode & confidence
			Optional<ZapAlert> highestSeverityAlertOptional = entrySet.getValue().stream()
					.max(Comparator.comparing(ZapAlert::getRiskcode).thenComparing(ZapAlert::getConfidence));

			if (highestSeverityAlertOptional.isPresent() && !highestSeverityAlertOptional.isEmpty())
				highestSeverityAlert = highestSeverityAlertOptional.get();

			// description of the max alert			
			decription = Jsoup.parse( highestSeverityAlert.getDesc()).text();

			// name of the max alert with cwe-id like CWE-345:Content-Type Header Missing
			name = highestSeverityAlert.getName();

			// trimming name if length greater that 75 chars
			if (name.length() > 75)
				name = name.substring(0, Math.min(75, name.length()));

			// get riskcode String by riskcode numeric val
			importance = ZapApiConstants.RISK_CODE.getByValue(Integer.valueOf(highestSeverityAlert.getRiskcode()))
					.toString();
			
			if(Integer.valueOf(highestSeverityAlert.getRiskcode()) > 3){
				importance = ZapApiConstants.VERY_HIGH;				
			}
			
			remediation = Jsoup.parse( highestSeverityAlert.getSolution()).text();

			
			List<DetailRow> dataRowList = null;
			Map<String, Set<Instance>> pathToInstancesMap = new HashMap<>();

			for (ZapAlert alert : entrySet.getValue()) {
				if(ObjectUtils.isEmpty(dataRowList)) {
					dataRowList = createDetailsRow(alert, pathToInstancesMap);
				}else {
					dataRowList.addAll(createDetailsRow(alert, pathToInstancesMap));
				}
				
			}

			var evaluation = generateEvaluation(remediation, dataRowList, asset, assetProfile, importance, highestSeverityAlert.getRiskcode(), decription, code, name, highestSeverityAlert, pathToInstancesMap);
			LOGGER.info("Evaluation {}",evaluation);
			evaluationList.add(evaluation);
		}

		List<Evaluation> evaluationCacheListNoDuplicates = evaluationList.stream().distinct()
				.filter(ev -> ev.getCode() != null).toList();
		LOGGER.debug("{} |  evaluation list size: {}", assetProfile.getUuid(), evaluationList.size());
		LOGGER.info("exit  generateEvaluations()");
		return evaluationCacheListNoDuplicates;
	}

	private List<DetailRow> createDetailsRow(ZapAlert alert, Map<String, Set<Instance>> pathToInstancesMap) {
		Set<String> paths = new LinkedHashSet<>();
		Set<Instance> instanceList = new LinkedHashSet<>();
		List<String> list = new ArrayList<>();
		List<List<String>> detailsList = new ArrayList<>();
		list.add(alert.getName());
		list.add(alert.getRiskdesc());
		var instances = alert.getInstances();
		for (Instance instance : instances) {
			instanceList.add(instance);
			paths.add(instance.getUri());
			pathToInstancesMap.putIfAbsent(instance.getUri(), new HashSet<>());
			pathToInstancesMap.get(instance.getUri()).add(instance);
		}
		var instancesStr = new Gson().toJson(instanceList);
		list.add(String.join(", ", paths));		
		list.add(Jsoup.parse(alert.getSolution()).text());
		list.add(Jsoup.parse(alert.getReference()).text());
		list.add(Jsoup.parse(alert.getOtherinfo()).text());
		list.add(instancesStr);
		
		
		detailsList.add(list);
		List<List<String>> detailsList1 = new ArrayList<>(new LinkedHashSet<>(detailsList));

		List<DetailRow> detailRowList = new ArrayList<>();
		for (List<String> detail : detailsList1) {
			var detailRow1 = DetailRow.newBuilder().addAllData(detail).build();
			detailRowList.add(detailRow1);
		}
		return detailRowList;
	
	}

	private void getAlerts(List<String> includedContexts, ArrayList<Site> sites, ArrayList<ZapAlert> mergedSitesAlert) {
		for (Site site : sites) {

			if (includedContexts == null) {

				mergedSitesAlert.addAll(site.getAlerts());

			} else {
				if (checkIfSiteInContext(site.getHost(), includedContexts)) {

					mergedSitesAlert.addAll(site.getAlerts());
				}
			}

		}
	}

	private boolean checkIfSiteInContext(String siteName, List<String> includedContexts) {
		for (String context : includedContexts) {
			if (context.contains(siteName))
				return true;
		}
		return false;
	}

	private  Evaluation generateEvaluation(String solutions,List<DetailRow>  detailRowList, Asset asset, AssetProfile assetProfile,
										   String importance, String originalSeverity, String description, String code, String name, ZapAlert alert, Map<String, Set<Instance>> pathToInstancesMap) {
		if(importance.equalsIgnoreCase("INFORMATIONAL")|| importance.contains("Information")) {
			
			importance = "INFORMATION";
		}

		var findingFailures = makeAssetProfileFindings(detailRowList, assetProfile.getUuid(), alert, pathToInstancesMap);
		

		var result1 = AssetResult.newBuilder().setAssetUuid(asset.getUuid())
				.setAttributesUuid(assetProfile.getAttributesUuid()).setAsset(asset.getMasterAsset())
				.setProfileUuid(assetProfile.getUuid()).addAllDetails(detailRowList).build();
		
		return Evaluation.newBuilder().setDescription(description).setStandard("STANDARD").setCode(code).setName(name)
				.setCategory(Category.VULNERABILITY.toString())
				.setBaseData(ByteString.copyFromUtf8(new Gson().toJson(alert)))
				.setImportance(importance)
				.setOriginalSeverity(originalSeverity)
				.setRemediation(solutions)
				.addAllDetailHeaders(ZapApiConstants.detailHeaders)
				.addAllDetailTypes(ZapApiConstants.detailTypes)
				.addAllDetailContexts(ZapApiConstants.detailContexts)
				.addFailures(result1).
				setFindings(EvalFindings.newBuilder().addAllFailures(findingFailures)).build();

	}

	/**
	 * This method will prepare a constant response in case there is a failure in
	 * authenticated scan and add it to Evaluations to be sent back to CE
	 *
	 * @param asset   - Asset details of the application to be scanned
	 * @param profile - Asset Profile details to be added in the response
	 * @return List<Evaluation> Constant response to be added to evaluation list
	 */
	public List<Evaluation> fetchUnauthenticatedScanResponse(Asset asset, AssetProfile profile) {
		LOGGER.info(
				"In fetchUnauthenticatedScanResponse() - [ Fetching response for Unauthenticated Scan: [Asset identifier - {}]",
				asset.getMasterAsset().getIdentifier());
		List<Evaluation> evaluationList = new ArrayList<>();
	
		List<String> detailsList = new ArrayList<>();
		detailsList.add(APP_AUTH_FAILURE_MESSAGE);
		detailsList.add(APP_AUTH_FAILURE_MESSAGE);
		detailsList.add(APP_AUTH_FAILURE_MESSAGE);
		detailsList.add(APP_AUTH_FAILURE_MESSAGE);
		detailsList.add(APP_AUTH_FAILURE_MESSAGE);
		detailsList.add(APP_AUTH_FAILURE_MESSAGE);
		detailsList.add(APP_AUTH_FAILURE_MESSAGE);

		List<DetailRow> detailRowList = new ArrayList<>();
		var detailRow = DetailRow.newBuilder().addAllData(detailsList).build();
		detailRowList.add(detailRow);

		var result1 = AssetResult.newBuilder().setAssetUuid(asset.getUuid())
				.setAttributesUuid(profile.getAttributesUuid()).setAsset(asset.getMasterAsset())
				.setProfileUuid(profile.getUuid()).addAllDetails(detailRowList).build();

		var findingFailures = makeAssetProfileFindings(detailRowList, profile.getUuid(), null, null);
		

		var evaluation = Evaluation.newBuilder().setDescription("zap Application Authentication Failure")
				.setStandard("STANDARD").setCode("APP_AUTH_FAILURE").setName("Authentication Failure")
				.setImportance("HIGH").addAllDetailHeaders(ZapApiConstants.detailHeaders).addAllDetailTypes(ZapApiConstants.detailTypes)
				.addAllDetailContexts(ZapApiConstants.detailContexts)
				.setCategory(Category.VULNERABILITY.toString())
				.addFailures(result1)
				.setFindings(EvalFindings.newBuilder().addAllFailures(findingFailures)).build();

		evaluationList.add(evaluation);
		return evaluationList;
	}
	
	private void sleepDuringRetries(int retry, int retryLimit){
        if(retry<=retryLimit){
            try {
                LOGGER.debug("Sleeping for {} milli second",ZapApiConstants.RETRY_SLEEP_DURATION);
                LOGGER.info("Retrying {} attempt. Total Retry Count {}", retry, ZapApiConstants.RETRY_COUNT);
                Thread.sleep(ZapApiConstants.RETRY_SLEEP_DURATION);
            } catch (InterruptedException e) {
               LOGGER.error("Thread Interrupted: {}", e.getMessage());
               Thread.currentThread().interrupt();
            }
        }
    }

	private List<AssetProfileFinding> makeAssetProfileFindings(List<DetailRow> details, String profileUuid, ZapAlert alert, Map<String, Set<Instance>> pathToInstancesMap) {
		List<AssetProfileFinding> findingList = new ArrayList<>();
		ZapAlert copyAlert = new ZapAlert();
		if (null != alert) {
			copyAlert = copyZapAlert(alert);
		}
		for (DetailRow data : details) {
			String[] paths = data.getData(2).split(", ");
			for (String individualPath : paths) {
				var trackingInfo = trackingUtil.createDefaultTrackingDetail(individualPath);
				var displayInfo = displayUtil.createDefaultDisplayIdentifier(individualPath);
				if (null != pathToInstancesMap) {
					copyAlert.setInstances(new ArrayList<>(pathToInstancesMap.get(individualPath)));
				}
				AssetProfileFinding finding = AssetProfileFinding.newBuilder().setProfileUuid(profileUuid)
						.setTrackingId(trackingInfo.getTrackingID())
						.setTrackingIdentifier(trackingInfo.getTrackingIdentifier())
						.setDisplayIdentifier(displayInfo.getDisplayIdentifier())
						.setDisplayIdentifierMetadata(ByteString.copyFrom(displayInfo.getDisplayIdentifierMetadata()))
						.addDetails(data)
						.setBaseData(ByteString.copyFromUtf8(new Gson().toJson(copyAlert))).build();
				findingList.add(finding);
			}
		}
		return findingList;
	    }

	private ZapAlert copyZapAlert(ZapAlert alert) {
		ZapAlert zapAlert = new ZapAlert();
		zapAlert.setPluginId(alert.getPluginId());
		zapAlert.setAlertRef(alert.getAlertRef());
		zapAlert.setAlert(alert.getAlert());
		zapAlert.setName(alert.getName());
		zapAlert.setRiskcode(alert.getRiskcode());
		zapAlert.setConfidence(alert.getConfidence());
		zapAlert.setRiskdesc(alert.getRiskdesc());
		zapAlert.setDesc(alert.getDesc());
		zapAlert.setCount(alert.getCount());
		zapAlert.setSolution(alert.getSolution());
		zapAlert.setOtherinfo(alert.getOtherinfo());
		zapAlert.setReference(alert.getReference());
		zapAlert.setCweid(alert.getCweid());
		zapAlert.setWascid(alert.getWascid());
		zapAlert.setSourceid(alert.getSourceid());
		return zapAlert;
	}

}
