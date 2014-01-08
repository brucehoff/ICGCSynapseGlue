package org.sagebionetworks;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.security.Key;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.zip.GZIPInputStream;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpException;
import org.apache.commons.httpclient.methods.DeleteMethod;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.httpclient.methods.PostMethod;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.JSONValue;
import org.sagebionetworks.client.SynapseClient;
import org.sagebionetworks.client.SynapseClientImpl;
import org.sagebionetworks.client.SynapseProfileProxy;
import org.sagebionetworks.client.exceptions.SynapseException;
import org.sagebionetworks.repo.model.PaginatedResults;
import org.sagebionetworks.repo.model.TeamMember;
import org.sagebionetworks.repo.model.UserGroupHeader;
import org.sagebionetworks.repo.model.UserProfile;
import org.sagebionetworks.repo.model.message.MessageToUser;

import com.sshtools.j2ssh.SftpClient;
import com.sshtools.j2ssh.SshClient;
import com.sshtools.j2ssh.authentication.AuthenticationProtocolState;
import com.sshtools.j2ssh.authentication.PasswordAuthenticationClient;
import com.sshtools.j2ssh.configuration.ConfigurationLoader;


 
/**
 *
 */
public class ICGCSynapseGlue {	
	
    public static void main( String[] args) throws SynapseException, UnsupportedEncodingException, IOException {
		  Boolean execute = new Boolean(getProperty("EXECUTE"));
		  
		  String synapseUserName = getProperty("SYNAPSE_USERNAME");
		  String synapsePassword = getProperty("SYNAPSE_PASSWORD");
		  String signupTeamId = getProperty("SIGNUP_TEAM_ID");
		  String approveTeamId = getProperty("APPROVE_TEAM_ID");
		  String googleGroupName = getProperty("APPROVED_GOOGLE_GROUP");
		  
		  // get the emails from DACO
		  List<String> dacoApproved = getDACOEmails();
		  
		  System.out.println("Read "+dacoApproved.size()+" emails from DACO");
	        // sync the team membership with the list from DACO
	        // i.e. the team membership should be exactly those users who
	        // (1) are in the sign-up team and (2) are in the DACO list
	        
	        SynapseClient synapseClient = createSynapseClient();
	        synapseClient.login(synapseUserName, synapsePassword);
	        Map<String,TeamMember> signedUpEmails = getTeamMemberEmails(synapseClient, signupTeamId);
	        System.out.println("Currently signed up for the challenge:\n"+signedUpEmails.keySet());
	        Map<String,TeamMember> approvedEmails = getTeamMemberEmails(synapseClient, approveTeamId);
	        System.out.println("Currently approved for the challenge:\n"+approvedEmails.keySet());
	        
	        // who is both signed up AND approved by DACO
	        // first get all the users who have signed up for the competition
	        Set<String> signedUpAndApprovedByDACO = new HashSet<String>(signedUpEmails.keySet());
	        // now intersect with those approved in DACO
	        signedUpAndApprovedByDACO.retainAll(dacoApproved);
	        System.out.println("Currently signed up and DACO-approved for the challenge:\n"+signedUpAndApprovedByDACO);
	        
	        // to figure out who to add, start with those who should be in the approved set...
	        Set<String> usersToAdd = new HashSet<String>(signedUpAndApprovedByDACO);
	        // ... now remove all who are already approved in Synapse
	        usersToAdd.removeAll(approvedEmails.keySet());
	        System.out.println("Emails we need to add in Synapse ("+usersToAdd.size()+"):\n"+usersToAdd);	        
	        
	        // to figure out who to remove, start with those who are in the approved set...
	        Set<String> usersToRemove = new HashSet<String>(approvedEmails.keySet());
	        // ... now remove those who are should be in the approved set
	        usersToRemove.removeAll(signedUpAndApprovedByDACO);
	        System.out.println("Emails we need to remove in Synapse (minus any team admin's, which we never remove) ("+usersToRemove.size()+"):\n"+usersToRemove);	 
	        
	        int removeCount = 0;
	        for (String email : usersToRemove) {
	        	TeamMember memberToRemove = approvedEmails.get(email);
	        	if (memberToRemove==null) throw new IllegalStateException();
	        	if (!memberToRemove.getIsAdmin()) {
	        		removeCount++;
	        		if (execute) synapseClient.removeTeamMember(approveTeamId, memberToRemove.getMember().getOwnerId());
	        	}
	        }
	        if (execute) {
	        	System.out.println("Done removing "+removeCount);
	        } else {
	        	System.out.println("Skipping removing "+removeCount+" because EXECUTE=false");
	        	
	        }
	        
			String myOwnUserId = synapseClient.getMyProfile().getOwnerId();
			
	        for (String email : usersToAdd) {
	        	TeamMember tm = signedUpEmails.get(email);
	        	if (tm==null) throw new IllegalStateException();
	        	
				UserGroupHeader ugh = tm.getMember();
				String displayName = ugh.getDisplayName();
				String idToAdd = ugh.getOwnerId();
				if (execute) {
					synapseClient.addTeamMember(approveTeamId, idToAdd);
					// now notify them, cc'ing our notification list
					String messageBody = "Dear "+displayName+",\n"+
							"You have been approved for participation in the ICGC-TCGA DREAM Mutation Calling challenge. "+
							"For further information please see https://www.synapse.org/#!Synapse:syn312572.\n"+
							"Sincerely,\n"+
							"Synapse Administration";
					MessageToUser message = new MessageToUser();
					message.setSubject("ICGC-TCGA DREAM Mutation Calling challenge");
					message.setRecipients(new HashSet<String>(Arrays.asList(new String[]{email,myOwnUserId})));
					synapseClient.sendStringMessage(message, messageBody);
				}
	        }
	        if (execute) {
	        	System.out.println("Done adding "+usersToAdd.size());
	        } else {
	        	System.out.println("Skipping adding "+usersToAdd.size()+" because EXECUTE=false");
	        }
	        
		  // now sync the approved group with the google group
		  // to figure out who to add, start with those who should be in the approved set...
	      Set<String> usersToAddInGoogle = new HashSet<String>(signedUpAndApprovedByDACO);
	      // ... now remove all who are already approved in Google
    	  String oauthToken = getOAuthAccessToken();
    	  Map<String, String> members = getGroupMembers(googleGroupName, "MEMBER", oauthToken);
		  Set<String> googleApprovedNonAdminEmails = members.keySet();
	      usersToAddInGoogle.removeAll(googleApprovedNonAdminEmails);
	      // skip any owners or managers that are in the set
	      usersToAddInGoogle.removeAll(getGroupMembers(googleGroupName, "OWNER", oauthToken).keySet());
	      usersToAddInGoogle.removeAll(getGroupMembers(googleGroupName, "MANAGER", oauthToken).keySet());
	      System.out.println("Emails we need to add in Google ("+usersToAddInGoogle.size()+"):\n"+usersToAddInGoogle);	
	      
	      int usersAddedToGoogleGroup = 0;
	      // add these to the Google group
	      for (String email : usersToAddInGoogle) {
	    	  if (execute) {
	    		  boolean success = addGroupMember(googleGroupName, email, "MEMBER", oauthToken);
	    		  if (success) usersAddedToGoogleGroup++;
	    	  }
	      }
	        
	      // to figure out who to remove, start with those who are in the Google Group (skipping any owners or managers)...
	      Set<String> usersToRemoveFromGoogle = new HashSet<String>(googleApprovedNonAdminEmails);
	      // ... now remove those who are in the approved set
	      usersToRemoveFromGoogle.removeAll(signedUpAndApprovedByDACO);
	      System.out.println("Emails we need to remove in Google ("+usersToRemoveFromGoogle.size()+"):\n"+usersToRemoveFromGoogle);
	      
	      // remove these from the Google group
	      for (String email : usersToRemoveFromGoogle) {
	    	  String memberKey = members.get(email);
	    	  if (memberKey==null) throw new IllegalStateException(email);
	     		if (execute) removeGroupMember(googleGroupName, memberKey, oauthToken);
	      }
	      
		  if (execute && (usersToAdd.size()>0 || removeCount>0 || usersAddedToGoogleGroup>0 || usersToRemoveFromGoogle.size()>0)) {
			  String messageBody = "Added "+usersToAdd.size()+" and removed "+removeCount+" users from Team "+approveTeamId+"\n";
			  messageBody += "Added "+usersAddedToGoogleGroup+" and removed "+usersToRemoveFromGoogle.size()+" from "+googleGroupName;
			  MessageToUser message = new MessageToUser();
			  message.setSubject("GMC Challenge approval");
			  message.setRecipients(new HashSet<String>(Arrays.asList(new String[]{myOwnUserId})));
			  synapseClient.sendStringMessage(message, messageBody);
		  }
		  
	  }
	  
	private static Properties properties = null;

	public static void initProperties() {
		if (properties!=null) return;
		properties = new Properties();
		InputStream is = null;
    	try {
    		is = ICGCSynapseGlue.class.getClassLoader().getResourceAsStream("global.properties");
    		properties.load(is);
    	} catch (IOException e) {
    		throw new RuntimeException(e);
    	} finally {
    		if (is!=null) try {
    			is.close();
    		} catch (IOException e) {
    			throw new RuntimeException(e);
    		}
    	}
   }
	
	public static String getProperty(String key) {
		initProperties();
		String commandlineOption = System.getProperty(key);
		if (commandlineOption!=null) return commandlineOption;
		String embeddedProperty = properties.getProperty(key);
		if (embeddedProperty!=null) return embeddedProperty;
		// (could also check environment variables)
		throw new RuntimeException("Cannot find value for "+key);
	}	

	  private static final int TEAM_PAGE_SIZE = 1000;
		
	  // returns a map from email to TeamMember object
	  private static Map<String,TeamMember> getTeamMemberEmails(SynapseClient synapseClient, String teamId) throws SynapseException {
	        PaginatedResults<TeamMember> members = synapseClient.getTeamMembers(teamId, null, TEAM_PAGE_SIZE, 0);
	        if (members.getTotalNumberOfResults()>members.getResults().size())
	        	throw new RuntimeException("Failed to retrieve all team members in one page.");
	        Map<String,TeamMember> emails = new HashMap<String,TeamMember>();
	        for (TeamMember m : members.getResults()) {
	        	UserProfile up = synapseClient.getUserProfile(m.getMember().getOwnerId());
	        	
	        	emails.put(up.getEmail(), m);
	        }
		  return emails;
	  }
	  
	  private static SynapseClient createSynapseClient() {
			boolean staging = false;
			SynapseClientImpl scIntern = new SynapseClientImpl();
			if (staging) {
				scIntern.setAuthEndpoint("https://repo-staging.prod.sagebase.org/auth/v1");
				scIntern.setRepositoryEndpoint("https://repo-staging.prod.sagebase.org/repo/v1");
				scIntern.setFileEndpoint("https://repo-staging.prod.sagebase.org/file/v1");
			} else { // prod
				scIntern.setAuthEndpoint("https://repo-prod.prod.sagebase.org/auth/v1");
				scIntern.setRepositoryEndpoint("https://repo-prod.prod.sagebase.org/repo/v1");
				scIntern.setFileEndpoint("https://repo-prod.prod.sagebase.org/file/v1");
			}
			return SynapseProfileProxy.createProfileProxy(scIntern);

	  }
	  
	  private static List<String> getDACOEmails() {
		  List<String> lines = getDACOUserFile();
	        List<String> emails = new ArrayList<String>();
	        for (String line : lines) {
	        	if (line.equals("user name,openid,email")) continue;
	        	String[] fields = line.split(",");
	        	if (fields.length!=3) throw new RuntimeException("Unexpected row: "+line);
	        	// user name,openid,email so skip first field, take third field, and take 2nd field only if is email
	        	if (openIdIsEmail(fields[1])) emails.add(fields[1]);
	        	emails.add(fields[2]);
	        }
		  return emails;
	  }
	  
	  /**
	   * return true iff the openId string is an email address
	   * @param openId
	   * @return
	   */
	    private static boolean openIdIsEmail(String openId) {
	    	if (openId.indexOf("@")>=0) return true;
	    	if (openId.indexOf("http://")>=0) return false;
	    	if (openId.indexOf("https://")>=0) return false;
	    	if (openId.endsWith(".myopenid.com")) return false;
	    	if (openId.endsWith(".verisignlabs.com")) return false;
	    	throw new IllegalArgumentException("Unrecognized OpenID: "+openId);
	    }
	    
	  /**
	   * read the DACO User file and return as a list of strings
	   * @return
	   * @throws Exception
	   */
	  public static List<String> getDACOUserFile() {
	    try {
			String hostname = getProperty("DACO_HOSTNAME");
			String username = getProperty("DACO_USERNAME");
			String password = getProperty("DACO_PASSWORD");
			String filename = getProperty("DACO_FILENAME");
	        String secretString = getProperty("DACO_SECRET_KEY");
	        String ivString =     getProperty("DACO_IV");
			String folder = "//dream-auth/";
		      
	        ConfigurationLoader.initialize(false);
	
	        // Make a client connection
	        SshClient ssh = new SshClient();
	        // Connect to the host
	        ssh.connect(hostname);
	        // Create a password authentication instance
	        PasswordAuthenticationClient pwd = new PasswordAuthenticationClient();
	        pwd.setUsername(username);
	        pwd.setPassword(password);
	        int result = ssh.authenticate(pwd);
	        if (result != AuthenticationProtocolState.COMPLETE)  throw new Exception("Unable to authenticate.");
	        SftpClient sftp = ssh.openSftpClient();
	        sftp.cd(folder);
	        ByteArrayOutputStream baos = new ByteArrayOutputStream();
	        sftp.get(filename, baos);
	        ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
	        GZIPInputStream gzis = new GZIPInputStream(bais);
	        List<String> lines = decrypt(secretString, ivString, gzis);
	        sftp.quit();
	        ssh.disconnect();
	        return lines;
	  	} catch (Exception e) {
			throw new RuntimeException(e);
		}
	  }
    
    /**
     * decrypt file and return lines as a list of strings
     * 
     * @param secretString
     * @param ivString
     * @param is
     * @return
     * @throws Exception
     */
    private static List<String> decrypt(String secretString, String ivString, InputStream is) {
    	try {
            Cipher c;
            Key k;
            byte[] secret = hexStringToByteArray(secretString);
            byte[] iv = hexStringToByteArray(ivString);

            c = Cipher.getInstance("AES/CBC/NoPadding"); // The encryption level is aes-128-cbc 
            k = new SecretKeySpec(secret, "AES");
            c.init(Cipher.DECRYPT_MODE, k, new IvParameterSpec(iv));

            CipherInputStream cis = new CipherInputStream(is, c);
            BufferedReader br = new BufferedReader(new InputStreamReader(cis));

            List<String> ans = new ArrayList<String>();
            String line;
            while ((line = br.readLine()) != null) {
                ans.add(line);
            }
            br.close();

            return ans;
    	} catch (Exception e) {
    		throw new RuntimeException(e);
    	}
    }
    
    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                                 + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }
    
    /**
     * Uses the client ID, secret and a refresh token, stored as properties, to get an OAuth 2.0 access token
     * The refresh token must be generated for a suitably enabled project/application under the Google Apps account
     * to be accessed and the refresh token must be generated using the scope https://www.googleapis.com/auth/admin.directory.group
     * as per the Directory API.  To generate the refresh token use the oauth2.py utility:
     * http://code.google.com/p/google-mail-oauth2-tools/wiki/OAuth2DotPyRunThrough
     * python oauth2.py --client_id=<<clientid>> --client_secret=<<clientSecret>> --generate_oauth2_token --scope=https://www.googleapis.com/auth/admin.directory.group
     * 
     * @return an access token to authenticate/authorize requests to the Google API
     * @throws HttpException
     * @throws IOException
     */
    private static String getOAuthAccessToken() throws HttpException, IOException {
    	  HttpClient client = new HttpClient();
    	  PostMethod method = new PostMethod("https://accounts.google.com/o/oauth2/token");
    	  method.setParameter("client_id", getProperty("OAUTH_CLIENT_ID"));
    	  method.setParameter("client_secret", getProperty("OAUTH_CLIENT_SECRET"));
    	  method.setParameter("refresh_token", getProperty("OAUTH_REFRESH_TOKEN"));
    	  method.setParameter("grant_type", "refresh_token");
    	  client.executeMethod(method);
    	  String response = method.getResponseBodyAsString();
    	  JSONObject obj=(JSONObject)JSONValue.parse(response);
    	  return (String)obj.get("access_token");
      }
      
      /**
       * get the members of a google group
       * @param groupName must be URL Encoded
       * @param role filter on results.  One of MEMBER, MANAGER, OWNER
       * @param oauthToken  the token returned by getOAuthAccessToken()
       * @return a map from member email address to memberKey
       * @throws HttpException
       * @throws IOException
       */
      private static Map<String, String> getGroupMembers(String groupName, String role, String oauthToken)  throws HttpException, IOException {
      	  HttpClient client = new HttpClient();
      	  String url = "https://www.googleapis.com/admin/directory/v1/groups/"+groupName+"/members?roles="+role;
      	  GetMethod method = new GetMethod(url);
      	  method.addRequestHeader("Authorization", "Bearer "+oauthToken);
      	  int rc = client.executeMethod(method);
    	  String response = method.getResponseBodyAsString();
    	  if (rc!=200) {
        	  	throw new RuntimeException("URL: "+url+"\n"+
      			  "Response code: "+rc+"\n"+
      			  "Response: "+method.getResponseBodyAsString());
      	  }
    	  JSONObject obj=(JSONObject)JSONValue.parse(response);
    	  JSONArray memberJSON = (JSONArray)obj.get("members");
    	  Map<String, String> members = new HashMap<String, String>();
      	  for (int i=0; memberJSON!=null && i<memberJSON.size(); i++) {
      		  JSONObject m = (JSONObject)memberJSON.get(i);
         	  members.put((String)m.get("email"), (String)m.get("id"));
      	  }
      	  return members;
      }
      
      /**
       * The API seems to have a bug in which a certain user not in the group is mistakenly taken
       * to be a group member, throwing a 409 error. We suppress throwing exceptions for 409s,
       * which means this method is idempotent
       * 
       * @param groupName must be URL Encoded
       * @param email the email address of the member to add NOT URL encoded
       * @param role one of MEMBER, MANAGER, OWNER
       * @param oauthToken the token returned by getOAuthAccessToken()
       * @return true if and only if successful
       * @throws HttpException
       * @throws IOException
       */
      private static boolean addGroupMember(String groupName, String email, String role, String oauthToken) throws HttpException, IOException {
    	  HttpClient client = new HttpClient();
    	  String url = "https://www.googleapis.com/admin/directory/v1/groups/"+groupName+"/members";
    	  PostMethod method = new PostMethod(url);
    	  JSONObject requestJSON = new JSONObject();
    	  requestJSON.put("email", email);
    	  requestJSON.put("role", role);
    	  String requestBody = requestJSON.toString();
    	  method.addRequestHeader("Content-type", "application/json; charset=UTF-8");
    	  method.addRequestHeader("Authorization", "Bearer "+oauthToken);
    	  method.setRequestBody(requestBody);
    	  int rc = client.executeMethod(method);
    	  String webDump =  "URL: "+url+"\n"+
    			  "Request Body: "+requestBody+"\n"+
    			  "Response code: "+rc+"\n"+
    			  "Response: "+method.getResponseBodyAsString();
    	  if (rc==409) {
    		  System.out.println(webDump);
    		  return false;
    	  } else if (rc!=200 && rc!=201) {
      	  	throw new RuntimeException(webDump);
    	  }
    	  return true;
      }
      
      /**
       * Remove a member from a google group
       * @param groupName must be URL Encoded
       * @param memberKey must be the member ID or the member's email address, URL Encoded
       * @param oauthToken the token returned by getOAuthAccessToken()
       * @throws HttpException
       * @throws IOException
       */
      private static void removeGroupMember(String groupName, String memberKey, String oauthToken) throws HttpException, IOException {
      	HttpClient client = new HttpClient();
      	String url = "https://www.googleapis.com/admin/directory/v1/groups/"+groupName+"/members/"+memberKey;
      	DeleteMethod method = new DeleteMethod(url);
      	method.addRequestHeader("Authorization", "Bearer "+oauthToken);
          int rc = client.executeMethod(method);
          if (rc!=200 && rc!=204) {
        	  throw new RuntimeException("URL: "+url+"\n"+
        			  "Response code: "+rc+"\n"+
        			  "Response: "+method.getResponseBodyAsString());
          }
      }
      

}

