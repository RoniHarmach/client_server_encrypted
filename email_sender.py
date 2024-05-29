import smtplib
import ssl
import sys
import uuid
from email.message import EmailMessage
import base64


class EmailSender:

    email_sender: str = None
    password: str = None
    pass_enc: str = None

    def __init__(self, email_sender, password):
        self.email_sender = email_sender
        self.password = password
        self.pass_enc = ''.join([e.decode()[:2] for e in [base64.b64encode(m.encode()) for m in password]])


    def send_email(self, email_receiver, email_subject, email_body):
        em = EmailMessage()
        em['from'] = self.email_sender
        em['To'] = email_receiver
        em['Subject'] = email_subject
        em.set_content(email_body)
        context = ssl.create_default_context()

        with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context) as smtp:
            email_password = ''.join([base64.b64decode(e).decode() for e in [self.pass_enc[i:i+2]+'==' for i in range(0, len(self.pass_enc), 2)]])
            smtp.login(self.email_sender, email_password)
            smtp.sendmail(self.email_sender, email_receiver, em.as_string())


def main(email_sender, password):
    sender = EmailSender(email_sender, password)
    sender.send_email("roni.harmach@gmail.com", "Important", "My name is inigo montoya, you killd my father. prepare to die")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])