package org.sagebionetworks;

import java.util.Arrays;
import java.util.Collections;

import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.services.simpleemail.AmazonSimpleEmailService;
import com.amazonaws.services.simpleemail.AmazonSimpleEmailServiceClient;
import com.amazonaws.services.simpleemail.model.Body;
import com.amazonaws.services.simpleemail.model.Content;
import com.amazonaws.services.simpleemail.model.Destination;
import com.amazonaws.services.simpleemail.model.Message;
import com.amazonaws.services.simpleemail.model.SendEmailRequest;

public class AWSSendEmail {
    public static void sendEmail(String sender, String recipient, 
	String replyTo, String subject, String bodyMsg)
    {
		  String AWS_ACCESS_KEY = System.getenv("AWS_ACCESS_KEY");
		  String AWS_SECRET_KEY = System.getenv("AWS_SECRET_KEY");
        Body body = new Body();
        body.setHtml( new Content( bodyMsg ) );
        Content content = new Content(subject);
        Message message = new Message( content, body );
        SendEmailRequest req = new SendEmailRequest( sender,
                new Destination( Arrays.asList(recipient.split(",")) ),
                message );
        if (replyTo != null  && replyTo.trim().length() > 0)
            req.setReplyToAddresses( Collections.singleton( replyTo ) );
        AmazonSimpleEmailService sesService = new AmazonSimpleEmailServiceClient(
        		new BasicAWSCredentials(AWS_ACCESS_KEY, AWS_SECRET_KEY));
        sesService.sendEmail( req );
    }
}
