import argparse
import sys
import json

import flask

import xrules

app = flask.Flask(__name__)

web_ruleset = None

def runrules(msg, ruleset):
    r = xrules.makerules(ruleset)
    xrules.applyrules(r, msg, globals())

def selftest(msg, ruleset):
    runrules(msg, ruleset)

@app.route('/', methods=['POST'])
def webhook():
    msg = flask.request.get_json()
    if msg == None:
        data = list(flask.request.form.keys())[0]
        msg = json.loads(data)
    runrules(msg, web_ruleset)

    return "OK"

def main():
    global web_ruleset

    ruleset_default = "cipolice-example.rules"

    parser = argparse.ArgumentParser(description="CIPolicE")
    parser.add_argument("-w", "--web", action="store_true", help="Run as web service on port 10080.")
    parser.add_argument("-m", "--mq", action="store_true", help="Run as message queue client on port XXX.")
    parser.add_argument("-t", "--test", action="store_true", help="Run in self-test mode.")
    parser.add_argument("-r", "--ruleset", action="store", default=ruleset_default, help=f"Ruleset to use (default: {ruleset_default}).")
    parser.add_argument("msg", nargs="?")
    args = parser.parse_args()

    if args.web:
        web_ruleset = args.ruleset
        app.run(host="0.0.0.0", port=10080)
    elif args.mq:
        print("NOT IMPLEMENTED YET")
        exit(-1)
    elif args.test:
        msg = args.msg
        if not msg:
            msg = {"cve": "CVE-2020-7050", "clairresult": -1, "image": "node:12", "compromised": True}
        else:
            msg = json.loads(msg)
        selftest(msg, args.ruleset)
    else:
        print("No operation specified! Run with -h.", file=sys.stderr)
        exit(-1)

if __name__ == '__main__':
    main()
