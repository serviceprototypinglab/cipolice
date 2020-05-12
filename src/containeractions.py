import os

def mark(imagename):
    return os.system(f"./label.sh {imagename}")

def notify(imagename):
    print("NOTIFY maintainer! (if label maintainer was set in dockerfile? or via LDAP?)")
    return False
