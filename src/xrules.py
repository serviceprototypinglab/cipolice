import rule_engine
import time

colors = {
    "green":    "\u001b[32m",
    "yellow":   "\u001b[33m",
    "red":      "\u001b[31m",
    "blue":     "\u001b[34m",
    "reset":    "\u001b[0m"
}

def loadrules(rulesfile):
    rules = {}
    crule = None
    f = open(rulesfile)

    for line in f:
        line = line.strip("\r\n")
        if not line.startswith("\t"):
            crule = line
        else:
            line = line.strip()
            if crule:
                rules[crule] = rules.get(crule, []) + [line]
            else:
                raise Exception("invalid rules format")

    return rules

def makerules(rulesfile):
    rerules = {}
    rules = loadrules(rulesfile)

    for rule in rules:
        rerules[rule_engine.Rule(rule)] = rules[rule]

    return rerules

def applyrules(rerules, msg, g):
    print(colors["blue"] + "-----" + colors["reset"])
    print(colors["blue"] + "EVENT:" + str(msg) + colors["reset"])
    print(colors["blue"] + "@TIME:" + time.asctime() + colors["reset"])
    for rerule in rerules:
        if rerule.matches(msg):
            print(colors["green"] + "ACCEPT RULE:" + str(rerule) + colors["reset"])
            for action in rerules[rerule]:
                print(colors["yellow"] + "→ ACTION:" + action + colors["reset"])
                res = None
                try:
                    res = g[action](msg)
                except Exception as e:
                    print(colors["red"] + str(e) + colors["reset"])
                    res = -1
                if res is 0 or res is True:
                    print(colors["yellow"] + "  ACTION SUCCESS" + colors["reset"])
                else:
                    print(colors["red"] + "  ACTION FAIL" + colors["reset"])
        else:
            print(colors["red"] + "REJECT RULE:" + str(rerule) + colors["reset"])
