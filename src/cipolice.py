import argparse
import sys
from durable.lang import *
import containeractions

from flask import Flask
app = Flask(__name__)

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

@app.route('/')
def selftest():
    post("docker", {"cve": "CVE-2020-7050", "clairresult": -1, "image": "node:12", "compromised": "true"})
    return "OK"

def main():
    parser = argparse.ArgumentParser(description="CIPolicE")
    parser.add_argument("-w", "--web", action="store_true", help="Run as web service on port 10080.")
    parser.add_argument("-t", "--test", action="store_true", help="Run in self-test mode.")
    args = parser.parse_args()

    if args.web:
        app.run(host="0.0.0.0", port=10080)
    elif args.test:
        selftest()
    else:
        print("Not operation specified! Run with -h.", file=sys.stderr)

if __name__ == '__main__':
    main()
