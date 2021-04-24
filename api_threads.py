import requests
import smtplib
import ssl

username = ''
password = ''
sender = ''


def send_email(recipient_emails, subject, h1='Example email text.'):
    """Recipients as a list for iter."""

    body = f'{h1}'

    message = """\
    Subject: {}
    
    {}""".format(subject, body)

    context = ssl.create_default_context()

    # port 465 for ssl
    with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context) as server:
        server.login(username, password)
        for recipient in recipient_emails:
            server.sendmail(sender, recipient, message)

