package se.sikevux;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.util.Map.Entry;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.HttpsURLConnection;

/**
 *
 * @author Patrik 'Sikevux' Greco <sikevux@sikevux.se>
 */
public class JavaFlare {

	private String cloudflareUrl = "https://www.cloudflare.com/api_json.html";
	private String apiKey = "apikey";
	private String email = "email@example.com";
	private String apiEmailCall = "&tkn=" + apiKey + "&email=" + email;

	/**
	 * @param args the command line arguments
	 */
	public static void main(String[] args) {
		new JavaFlare().getStatus("sikevux.se", 20);
		new JavaFlare().getListDomains();
		new JavaFlare().getDNSDomain("sikevux.se");
		new JavaFlare().getRecentIPs("sikevux.se", 48, "r", true);
	}

	private void getStatus(String domain, int interval) {
		String postArguments = "a=stats&z=" + domain + "&interval=" + Integer.toString(interval) + apiEmailCall;
		new JavaFlare().doApiCall(postArguments);
	}

	private void getListDomains() {
		String postArguments = "a=zone_load_multi" + apiEmailCall;
		new JavaFlare().doApiCall(postArguments);
	}

	private void getDNSDomain(String domain) {
		String postArguments = "a=rec_load_all&z=" + domain + apiEmailCall;
		new JavaFlare().doApiCall(postArguments);
	}

	private void getRecentIPs(String domain, int hours, String classType, boolean geo) {
		StringBuilder stringBuilder = new StringBuilder();
		stringBuilder.append("a=zone_ips&z=" + domain);

		if (hours > 48) {
			hours = 48;
		}

		stringBuilder.append("&hours=" + Integer.toString(hours));

		if (classType.length() > 1) {
			switch (classType) {
				case "regular":
					classType = "r";
					break;
				case "crawler":
					classType = "s";
					break;
				case "threat":
					classType = "t";
					break;
			}
		}

		stringBuilder.append("&class=" + classType);

		if (geo) {
			stringBuilder.append("&geo=1");
		} else {
			stringBuilder.append("&geo=0");
		}

		stringBuilder.append(apiEmailCall);

		new JavaFlare().doApiCall(stringBuilder.toString());

	}

	private void getScore(String ip) {
		String postArguments = "a=ip_lkup&ip=" + ip + apiEmailCall;
		new JavaFlare().doApiCall(postArguments);
	}

	private void getSettingsDomain(String domain) {
		String postArguments = "a=zone_settings&z=" + domain + apiEmailCall;
		new JavaFlare().doApiCall(postArguments);
	}

	private void doApiCall(String postArguments) {

		URL url;
		String line;

		try {
			url = new URL(cloudflareUrl);
			HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
			connection.setDoOutput(true);
			connection.setDoInput(true);
			connection.setInstanceFollowRedirects(false);
			connection.setRequestMethod("POST");
			connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
			connection.setRequestProperty("charset", "utf-8");
			connection.setRequestProperty("Content-Length", "" + Integer.toString(postArguments.getBytes().length));
			connection.setUseCaches(false);

			DataOutputStream postWriter = new DataOutputStream(connection.getOutputStream());
			postWriter.writeBytes(postArguments);
			postWriter.flush();

			BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
			StringBuilder jsonOutput = new StringBuilder();
			while ((line = bufferedReader.readLine()) != null) {
				jsonOutput.append(line);
			}
			postWriter.close();
			bufferedReader.close();

			new JavaFlare().outputResult(jsonOutput.toString());

		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private void outputResult(String jsonData) {
		if (jsonData != null) {
			try {
				ObjectMapper mapper = new ObjectMapper();
				JsonFactory factory = mapper.getFactory();
				JsonParser parser = factory.createParser(jsonData);
				JsonNode rootNode = mapper.readTree(jsonData);
				JsonNode responseNode;
				JsonNode resultNode;

				Entry<String, JsonNode> fields;
				Entry<String, JsonNode> fieldsOld = null;
				String[] result;
				if ("success".equals(rootNode.get("result").asText().toString())) {
					System.out.println("Sucess!");
					responseNode = mapper.readTree(rootNode.get("response").toString());

					if (responseNode.has("ips")) {
						/**
						 * We got IP related response
						 */
						System.out.println("ips");
					} else if (responseNode.has("zones")) {
						/**
						 * We got Zones
						 *
						 * TODO: Implement rest of the response values
						 */
						System.out.println("--- Zones ---");
						for (int i = 0; i < responseNode.get("zones").get("count").asInt(); i++) {
							System.out.println("-- " + responseNode.get("zones").get("objs").get(i).get("display_name").asText() + " --");
							System.out.println(responseNode.get("zones").get("objs").get(i).get("zone_status_class").asText());
							System.out.println("Origin registrar: " + responseNode.get("zones").get("objs").get(i).get("orig_registrar").asText());
							System.out.println("Origin DNS host: " + responseNode.get("zones").get("objs").get(i).get("orig_dnshost").asText());
							System.out.println("Origin nameservers: " + responseNode.get("zones").get("objs").get(i).get("orig_ns_names").asText());
							if (responseNode.get("zones").get("objs").get(i).get("fqdns").size() > 0) {
								System.out.println("FQDNS: ");
								for (int j = 0; j < responseNode.get("zones").get("objs").get(i).get("fqdns").size(); j++) {
									System.out.println(responseNode.get("zones").get("objs").get(i).get("fqdns").get(j));
								}
							}
							System.out.println("- Properties -");

							System.out.println("PRO: " + intToBool(responseNode.get("zones").get("objs").get(i).get("props").get("pro").asInt()));
							System.out.println("SSL: " + intToBool(responseNode.get("zones").get("objs").get(i).get("props").get("ssl").asInt()));
							System.out.println("Alexa rank: " + responseNode.get("zones").get("objs").get(i).get("props").get("alexa_rank").asInt());

							System.out.println("- Allow -");
							for (int j = 0; j < responseNode.get("zones").get("objs").get(i).get("allow").size(); j++) {
								System.out.println(responseNode.get("zones").get("objs").get(i).get("allow").get(j).asText());
							}

						}

					} else if (responseNode.has("recs")) {
						/**
						 * Handle case with DNS records
						 *
						 */
						System.out.println("recs");
					} else if (responseNode.has("result")) {
						/**
						 * Handle case with Stats
						 *
						 * TODO: Implement rest of returned values
						 */
						System.out.println("--- Page Views ---");
						System.out.println("Regular: " + responseNode.get("result").get("objs").get(0).get("trafficBreakdown").get("pageviews").get("regular").toString() + " total, " + responseNode.get("result").get("objs").get(0).get("trafficBreakdown").get("uniques").get("regular").toString() + " unique");
						System.out.println("Threat: " + responseNode.get("result").get("objs").get(0).get("trafficBreakdown").get("pageviews").get("threat").toString() + " total, " + responseNode.get("result").get("objs").get(0).get("trafficBreakdown").get("uniques").get("threat").toString() + " unique");
						System.out.println("Crawler: " + responseNode.get("result").get("objs").get(0).get("trafficBreakdown").get("pageviews").get("crawler").toString() + " total, " + responseNode.get("result").get("objs").get(0).get("trafficBreakdown").get("uniques").get("crawler").toString() + " unique");

						System.out.println("--- Bandwidth Served ---");
						System.out.println(humanReadableByteCount(responseNode.get("result").get("objs").get(0).get("bandwidthServed").get("user").asLong() + responseNode.get("result").get("objs").get(0).get("bandwidthServed").get("cloudflare").asLong(), true) + " total, and CloudFlare served " + humanReadableByteCount(responseNode.get("result").get("objs").get(0).get("bandwidthServed").get("cloudflare").asLong(), true) + " of that");

						System.out.println("--- Requests Served ---");
						System.out.println(Integer.toString(responseNode.get("result").get("objs").get(0).get("requestsServed").get("user").asInt() + responseNode.get("result").get("objs").get(0).get("requestsServed").get("user").asInt()) + " total requests, of these CloudFlare saved:" + responseNode.get("result").get("objs").get(0).get("requestsServed").get("cloudflare").asText() + " requests");

						System.out.println("--- Options ---");
						System.out.print("Pro zone? ");
						System.out.println(responseNode.get("result").get("objs").get(0).get("pro_zone").asBoolean() ? "Yes" : "No");

						System.out.print("Security setting: ");
						System.out.println(responseNode.get("result").get("objs").get(0).get("userSecuritySetting").asText());

						System.out.print("Cache setting: ");
						switch (responseNode.get("result").get("objs").get(0).get("cache_lvl").asText()) {
							case "agg":
								System.out.println("Aggressive");
								break;
							default:
								System.out.println(responseNode.get("result").get("objs").get(0).get("cache_lvl").asText());
								break;
						}

					}


					/**
					 * TODO: Write better code.
					 */
					if (responseNode.has("response")) {
						resultNode = mapper.readTree(responseNode.fields().next().toString().split("\\=", 2)[1].toString());
//					while((fields = responseNode.fields().next()) != null) {
//						if(fieldsOld == fields) {
//							break;
//						}
//
//						result = fields.toString().split("\\=", 2);
//						System.out.println(result[1]);
//						fieldsOld = fields;
//					}
						System.out.println(resultNode.toString());
					}
				}

			} catch (Exception ex) {
				Logger.getLogger(JavaFlare.class.getName()).log(Level.SEVERE, null, ex);
			}
		}
	}

	private boolean intToBool(int i) {
		if (i == 0) {
			return false;
		} else {
			return true;
		}
	}

	public static String humanReadableByteCount(long bytes, boolean si) {
		bytes = bytes * (si ? 1000 : 1024);
		int unit = si ? 1000 : 1024;
		if (bytes < unit) {
			return bytes + " B";
		}
		int exp = (int) (Math.log(bytes) / Math.log(unit));
		String pre = (si ? "kMGTPE" : "KMGTPE").charAt(exp - 1) + (si ? "" : "i");
		return String.format("%.1f %sB", bytes / Math.pow(unit, exp), pre);
	}
}
