import rule_engine
import time
import os
import urllib.request

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
        if line.strip().startswith("#"):
            continue
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

    osparamlist = []
    funcparamlist = []
    obparams = ("image",)
    for obparam in obparams:
        if not obparam in msg:
            print(colors["red"] + "WARNING: Obligatory parameter " + obparam + " not present." + colors["reset"])
            continue
        v = msg[obparam]
        osparamlist.append(f"'{v}'")
        funcparamlist.append(f"\"{v}\"")
    funcparamlist = ", ".join(funcparamlist)
    osparamlist = " ".join(osparamlist)

    needsbreak = False
    for rerule in rerules:
        if needsbreak:
            break
        hasmatch = False
        try:
            hasmatch = rerule.matches(msg)
        except Exception as e:
            # TODO differentiate better between: rule does not match / rule cannot match
            #print("E", e)
            pass
        if hasmatch:
            print(colors["green"] + "ACCEPT RULE:" + str(rerule) + colors["reset"])
            for action in rerules[rerule]:
                print(colors["yellow"] + "→ ACTION:" + action + colors["reset"])
                if action == "break":
                    needsbreak = True
                    print(colors["blue"] + "BREAK" + colors["reset"])
                    break
                res = None
                try:
                    if action.endswith(".sh"):
                        res = os.system(f"{action} {osparamlist}")
                    elif ".py:" in action:
                        mod, func = action.split(":")
                        impcmd = f"import {mod[:-3]}"
                        #print("IMPORT", impcmd)
                        exec(impcmd)
                        if " " in func:
                            func, *params = func.split(" ")
                            nparams = []
                            for param in params:
                                if param.startswith("{") and param.endswith("}"):
                                    if param[1:-1] in msg:
                                        param = msg[param[1:-1]]
                                nparams.append(param)
                            params = [f"\"{param}\"" for param in nparams]
                            funcparamlist = ",".join(params)
                        funccmd = f"a = {mod[:-3]}.{func}({funcparamlist})"
                        #print("INVOKE", funccmd)
                        exec(funccmd)
                        res = eval("a")
                    elif "http://" in action or "https://" in action:
                        data = str(msg)
                        req = urllib.request.Request(action, bytes(data, "utf-8"))
                        res = urllib.request.urlopen(req)
                    else:
                        res = g[action](msg)
                except Exception as e:
                    print(colors["red"] + "E:" + str(e) + colors["reset"])
                    res = -1
                if res is 0 or res is True:
                    print(colors["yellow"] + "  ACTION SUCCESS" + colors["reset"])
                else:
                    print(colors["red"] + "  ACTION FAIL" + colors["reset"])
        else:
            print(colors["red"] + "REJECT RULE:" + str(rerule) + colors["reset"])
