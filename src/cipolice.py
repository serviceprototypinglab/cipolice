from durable.lang import *
import containeractions

with ruleset("docker"):
    # ... when_all / when_any (and / or semantics)
    # ... @when_all(m.subject.matches('3[47][0-9]{13}'))
    # ... @when_all((m.predicate == 'is') & (m.object == 'frog'))
    # ... sequence: c.first, c.second, c.third, ...
    # ... none(m.t == 'balance')
    # ... priorities: @when_all(pri(3), m.amount < 300)

    @when_all(m.cve != "")
    def mark_image(c):
        print(f"React on {c.m.cve} by marking image")
        containeractions.mark("test-image")

    @when_all(m.compromised == "true")
    def notify_maintainer(c):
        print(f"React on {c.m.cve} by notifying maintainer")
        containeractions.notify("test-image")

post("docker", {"cve": "CVE-2020-7050"})
