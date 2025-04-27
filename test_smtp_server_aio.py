# test_smtp_server_aio.py
import os
import sys
import asyncio
from datetime import datetime
from aiosmtpd.controller import Controller
from email import message_from_bytes, policy

class CustomHandler:
    async def handle_DATA(self, server, session, envelope):
        """Process received messages and save them to files."""
        print(f"\n{'='*60}")
        print(f"Received email from: {envelope.mail_from}")
        print(f"Sent to: {', '.join(envelope.rcpt_tos)}")
        
        try:
            # Create emails directory if it doesn't exist
            os.makedirs('received_emails', exist_ok=True)
            
            # Parse the email
            data = envelope.content
            msg = message_from_bytes(data, policy=policy.default)
            subject = msg.get('Subject', 'No Subject')
            print(f"Subject: {subject}")
            
            # Create a timestamp for the filename
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"received_emails/email_{timestamp}.eml"
            
            # Save the email to a file
            with open(filename, 'wb') as f:
                f.write(data)
            
            print(f"Email saved to: {filename}")
            
            # Save email content (text and html)
            email_text = None
            email_html = None
            
            for part in msg.walk():
                if part.get_content_maintype() == 'text':
                    if part.get_content_subtype() == 'plain':
                        email_text = part.get_content()
                    elif part.get_content_subtype() == 'html':
                        email_html = part.get_content()
                
                # If the email has attachments, save them separately
                if part.get_content_disposition() == 'attachment':
                    # Get the filename of the attachment
                    attachment_filename = part.get_filename()
                    if attachment_filename:
                        attachment_path = f"received_emails/attachment_{timestamp}_{attachment_filename}"
                        with open(attachment_path, 'wb') as f:
                            f.write(part.get_payload(decode=True))
                        print(f"Attachment saved to: {attachment_path}")
            
            # Save plain text content
            if email_text:
                text_filename = f"received_emails/email_{timestamp}.txt"
                with open(text_filename, 'w', encoding='utf-8') as f:
                    f.write(email_text)
                print(f"Email text saved to: {text_filename}")
            
            # Save HTML content
            if email_html:
                html_filename = f"received_emails/email_{timestamp}.html"
                with open(html_filename, 'w', encoding='utf-8') as f:
                    f.write(email_html)
                print(f"Email HTML saved to: {html_filename}")
            
            print(f"{'='*60}\n")
            
            return '250 Message accepted for delivery'
        
        except Exception as e:
            print(f"Error processing message: {e}")
            return '500 Error processing message'

def main():
    # Set up the SMTP server
    handler = CustomHandler()
    server_port = 25  # Standard SMTP port
    
    # On some systems, you might need admin/root permissions for port 25
    # If you get permission errors, try using port 1025 instead
    if len(sys.argv) > 1:
        server_port = int(sys.argv[1])
    
    controller = Controller(handler, hostname='0.0.0.0', port=server_port)
    
    # Start the server
    print(f"Starting SMTP test server on port {server_port}...")
    print("Press Ctrl+C to stop the server.")
    print("Received emails will be saved to the 'received_emails' folder")
    
    try:
        controller.start()
        
        # Keep the server running until Ctrl+C
        while True:
            asyncio.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down server...")
    finally:
        controller.stop()

if __name__ == '__main__':
    main()
