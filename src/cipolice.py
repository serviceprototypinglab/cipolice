import argparse
import sys
import json
import subprocess
import time

try:
    import flask
except:
    print("(Warning: no web mode due to missing flask.)")

try:
    import pika
except:
    print("(Warning: no message queue mode due to missing pika.)")

import xrules

if "flask" in globals():
    app = flask.Flask(__name__)

web_ruleset = None

def augment(msg):
    try:
        p = subprocess.run(f"docker inspect {msg['image']} | jq '.[0].Config.Labels.maintainer'", shell=True, stdout=subprocess.PIPE)
    except Exception as e:
        print("(augment failed) " + str(e))
        return msg
    maint = p.stdout.decode().strip()
    if maint != "null":
        maint = maint[1:-1]
    else:
        maint = None
    msg["maintainer"] = maint
    print("(augment)", maint)
    return msg

def runrules(msg, ruleset):
    t_p1 = time.time()
    msg = augment(msg)
    t_p2 = time.time()
    r = xrules.makerules(ruleset)
    t_p3 = time.time()
    xrules.applyrules(r, msg, globals())
    t_p4 = time.time()
    print("(timing) augment", t_p2 - t_p1, "load", t_p3 - t_p2, "apply", t_p4 - t_p3, "s")

if "flask" in globals():
    @app.route('/', methods=['POST'])
    def webhook():
        msg = flask.request.get_json()
        if msg == None:
            data = list(flask.request.form.keys())[0]
            msg = json.loads(data)
        runrules(msg, web_ruleset)

        return "OK"

def queueloop(ruleset):
    print(" * Listening to AMQP...")

    wait = 1
    while True:
        try:
            connection = pika.BlockingConnection()
        except:
            print(f"- not yet ready; wait {wait}s...")
            time.sleep(wait)
            wait *= 1.5
            wait = int(wait * 10) / 10
        else:
            break

    channel = connection.channel()

    while True:
        try:
            for method_frame, properties, body in channel.consume("hello"):
                #print(method_frame, properties, body, type(body))
                msg = json.loads(body.decode())
                channel.basic_ack(method_frame.delivery_tag)
                runrules(msg, ruleset)
        except:
            print("- queue presumably not yet ready; wait 1s")
            time.sleep(1)

    #requeued_messages = channel.cancel()
    #connection.close()

def main():
    global web_ruleset

    ruleset_default = "cipolice-example.rules"

    parser = argparse.ArgumentParser(description="CIPolicE")
    if "flask" in globals():
        parser.add_argument("-w", "--web", action="store_true", help="Run as web service on port 10080/HTTP.")
    if "pika" in globals():
        parser.add_argument("-m", "--mq", action="store_true", help="Run as message queue client on port 5672/AMQP.")
    parser.add_argument("-t", "--test", action="store_true", help="Run in self-test mode.")
    parser.add_argument("-r", "--ruleset", action="store", default=ruleset_default, help=f"Ruleset to use (default: {ruleset_default}).")
    parser.add_argument("msg", nargs="?")
    args = parser.parse_args()

    if args.web:
        web_ruleset = args.ruleset
        app.run(host="0.0.0.0", port=10080)
    elif args.mq:
        queueloop(args.ruleset)
    elif args.test:
        msg = args.msg
        if not msg:
            msg = {"cve": "CVE-2020-7050", "clairresult": -1, "image": "nginx:latest", "compromised": True}
        else:
            msg = json.loads(msg)
        runrules(msg, args.ruleset)
    else:
        print("No operation specified! Run with -h.", file=sys.stderr)
        exit(-1)

if __name__ == '__main__':
    main()
