package org.sagebionetworks;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.security.Key;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.zip.GZIPInputStream;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.sagebionetworks.client.SynapseClient;
import org.sagebionetworks.client.SynapseClientImpl;
import org.sagebionetworks.client.SynapseProfileProxy;
import org.sagebionetworks.client.exceptions.SynapseException;
import org.sagebionetworks.repo.model.PaginatedResults;
import org.sagebionetworks.repo.model.TeamMember;
import org.sagebionetworks.repo.model.UserGroupHeader;
import org.sagebionetworks.repo.model.UserGroupHeaderResponsePage;
import org.sagebionetworks.repo.model.UserProfile;

import com.sshtools.j2ssh.SftpClient;
import com.sshtools.j2ssh.SshClient;
import com.sshtools.j2ssh.authentication.AuthenticationProtocolState;
import com.sshtools.j2ssh.authentication.PasswordAuthenticationClient;
import com.sshtools.j2ssh.configuration.ConfigurationLoader;

/**
 * TODO send email notification for any additions, removals or errors
 */
public class ICGCSynapseGlue {	
	  public static void main( String[] args) throws SynapseException, UnsupportedEncodingException {
		  Boolean execute = new Boolean(System.getProperty("EXECUTE"));
		  
		  String synapseUserName = System.getenv("SYNAPSE_USERNAME");
		  String synapsePassword = System.getenv("SYNAPSE_PASSWORD");
		  String signupTeamId = System.getenv("SIGNUP_TEAM_ID");
		  String approveTeamId = System.getenv("APPROVE_TEAM_ID");
		  String emailFrom = System.getenv("SMTP_FROM");
		  String emailTo = System.getenv("SMTP_TO");
		  
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
	        Set<String> signedUpAndApproved = new HashSet<String>(signedUpEmails.keySet());
	        // now intersect with those approved in DACO
	        signedUpAndApproved.retainAll(dacoApproved);
	        System.out.println("Currently signed up and DACO-approved for the challenge:\n"+signedUpAndApproved);
	        
	        // to figure out who to add, start with those who should be in the approved set...
	        Set<String> usersToAdd = new HashSet<String>(signedUpAndApproved);
	        // ... now remove all who are already approved
	        usersToAdd.removeAll(approvedEmails.keySet());
	        System.out.println("Emails we need to add ("+usersToAdd.size()+"):\n"+usersToAdd);	        
	        
	        // to figure out who to remove, start with those who are in the approved set...
	        Set<String> usersToRemove = new HashSet<String>(approvedEmails.keySet());
	        // ... now remove those who are should be in the approved set
	        usersToRemove.removeAll(signedUpAndApproved);
	        System.out.println("Emails we need to remove (skipping any admin's) ("+usersToRemove.size()+"):\n"+usersToRemove);	 
	        
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
	        
	        for (String email : usersToAdd) {
	        	UserGroupHeaderResponsePage page = synapseClient.getUserGroupHeadersByPrefix(email);
				List<UserGroupHeader> ughs = page.getChildren();
				if (ughs.size()!=1) throw new RuntimeException("Unexpected number of results "+ughs.size());
				UserGroupHeader ugh = ughs.get(0);
				String displayName = ugh.getDisplayName();
				String idToAdd = ugh.getOwnerId();
				if (execute) {
					synapseClient.addTeamMember(approveTeamId, idToAdd);
					// now notify them, cc'ing our notification list
					AWSSendEmail.sendEmail(emailFrom, email+","+emailTo, null,
							"ICGC-TCGA DREAM Mutation Calling challenge",
							// TODO get the carriage returns to work right
							"Dear "+displayName+",\n"+
							"You have been approved for participation in the ICGC-TCGA DREAM Mutation Calling challenge. "+
							"For further information please see https://www.synapse.org/#!Synapse:syn312572.\n"+
							"Sincerely,\n"+
							"Synapse Administration"
							);
				}
	        }
	        if (execute) {
	        	System.out.println("Done adding "+usersToAdd.size());
	        } else {
	        	System.out.println("Skipping adding "+usersToAdd.size()+" because EXECUTE=false");
	        }
	        
		  if (execute && (usersToAdd.size()>0 || removeCount>0)) {
			  String message = "Added "+usersToAdd.size()+" and removed "+removeCount+" users from Team "+approveTeamId;
			  AWSSendEmail.sendEmail(emailFrom, emailTo, 
						null, "GMC Challenge approval", 
						message);
		  }
	  }
	  
		private static final int TEAM_PAGE_SIZE = 1000;
		
	  // returns a map from email to Synapse principal ID
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
			//scIntern.login("bruce.hoff@sagebase.org", "foo");
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
			String hostname = System.getenv("DACO_HOSTNAME");
			String username = System.getenv("DACO_USERNAME");
			String password = System.getenv("DACO_PASSWORD");
			String filename = System.getenv("DACO_FILENAME");
	        String secretString = System.getenv("DACO_SECRET_KEY");
	        String ivString =     System.getenv("DACO_IV");
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
}
