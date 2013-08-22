package se.sikevux;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.InputStreamReader;
import java.net.URL;
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

		if(geo) {
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
			while ((line = bufferedReader.readLine()) != null) {
				System.out.println(line);
			}
			postWriter.close();
			bufferedReader.close();


		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
