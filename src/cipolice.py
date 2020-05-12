import argparse
import sys
import json

import flask

# 1. durable_rules
from durable.lang import *
# 2. rule-engine
import xrules

import containeractions

app = flask.Flask(__name__)

web_ruleset = None
web_legacy = None

# 1. durable_rules
# -----------------------------------------------
with ruleset("docker"):
    # ... when_all / when_any (and / or semantics)
    # ... @when_all(m.subject.matches('3[47][0-9]{13}'))
    # ... @when_all((m.predicate == 'is') & (m.object == 'frog'))
    # ... sequence: c.first, c.second, c.third, ...
    # ... none(m.t == 'balance')
    # ... priorities: @when_all(pri(3), m.amount < 300)

    @when_all(m.cve != "")
    def mark_image(c):
        print(f"React on {c.m.cve} by marking image {c.m.image}")
        containeractions.mark(c.m.image)
        # FIXME: we should not have to do that to trigger the other rule...?
        # FIXME: find out if we can trigger multiple consequents per one antecedent (docs say no so...)
        c.assert_fact({"compromised": c.m.compromised})

    @when_all(m.compromised == "true")
    def notify_maintainer(c):
        print(f"React on {c.m.cve} by notifying maintainer")
        containeractions.notify(c.m.image)
# -----------------------------------------------

# 2. rule-engine
# -----------------------------------------------
def mark_image(m):
    print(f"React on cve={m['cve']} by marking image {m['image']}")
    return containeractions.mark(m['image'])

def notify_maintainer(m):
    print(f"React on compromised={m['compromised']} by notifying maintainer")
    return containeractions.notify(m['image'])
# -----------------------------------------------

def runrules(msg, ruleset, legacy):
    # 1. durable_rules
    if legacy:
        post("docker", msg)

    # 2. rule-engine
    r = xrules.makerules(ruleset)
    xrules.applyrules(r, msg, globals())

def selftest(msg, ruleset, legacy):
    runrules(msg, ruleset, legacy)

@app.route('/', methods=['POST'])
def webhook():
    data = list(flask.request.form.keys())[0]
    msg = json.loads(data)
    runrules(msg, web_ruleset, web_legacy)

    return "OK"

def main():
    global web_ruleset, web_legacy

    ruleset_default = "cipolice-example.rules"

    parser = argparse.ArgumentParser(description="CIPolicE")
    parser.add_argument("-w", "--web", action="store_true", help="Run as web service on port 10080.")
    parser.add_argument("-t", "--test", action="store_true", help="Run in self-test mode.")
    parser.add_argument("-l", "--legacy", action="store_true", help="Activate legacy durable_rules.")
    parser.add_argument("-r", "--ruleset", action="store", default=ruleset_default, help=f"Ruleset to use (default: {ruleset_default}).")
    parser.add_argument("msg", nargs="?")
    args = parser.parse_args()

    if args.web:
        web_ruleset = args.ruleset
        web_legacy = args.legacy
        app.run(host="0.0.0.0", port=10080)
    elif args.test:
        msg = args.msg
        if not msg:
            msg = {"cve": "CVE-2020-7050", "clairresult": -1, "image": "node:12", "compromised": True}
        else:
            msg = json.loads(msg)
        selftest(msg, args.ruleset, args.legacy)
    else:
        print("No operation specified! Run with -h.", file=sys.stderr)

if __name__ == '__main__':
    main()
