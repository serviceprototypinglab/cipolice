from typing import Counter
from datetime import datetime
import os
import requests
import pika
import json
import subprocess
import sys
import find


def get_names():
    link = 'https://hub.docker.com/v2/repositories/library/'
    names = []
    while True:
        data = json.loads(requests.get(link).text)
        if data['next'] is None:
            break
        link = data['next']
        for item in data['results']:
            if item['name'] not in names:
                names.append(item['name'])
    print(names[:10])
    return names[:10]


def cleanup(names):
    for image in names:
        subprocess.call(f'docker rmi {image}', shell=True)


def oc_find():
    b = subprocess.run('oc get all -o json', shell=True, stdout=subprocess.PIPE)
    images = find.extract_values(json.loads(b.stdout), 'image')
    for i in range(len(images)):
        if '@' in images[i]:
            new_item = images[i].split('@')[0] + ':latest'
            images[i] = new_item
    print(images)
    return(images)

def push(image, tag):
    subprocess.call(f'docker tag {image} localhost:5000/{image}-test', shell=True)
    subprocess.call(f'docker push localhost:5000/{image}-test', shell=True)
    p = subprocess.run(f'CLAIR_ADDR=http://localhost:6060 CLAIR_THRESHOLD=10 REGISTRY_INSECURE=TRUE JSON_OUTPUT=TRUE klar localhost:5000/{image}-test', shell=True, stdout=subprocess.PIPE)
    return json.loads(p.stdout)


def scan(image, tag):
    p = subprocess.run(f'TRIVY_NEW_JSON_SCHEMA=true trivy -q image -f json {image}:{tag}', shell=True, stdout=subprocess.PIPE)
    return json.loads(p.stdout)


def pull(image, tag):
    subprocess.call(f'docker pull {image}:{tag}', shell=True)
    p = push(image, tag)
    """
    try:
        images = oc_find()
        if f'{image}:{tag}' in images:
            print(f"Warning, image {image} is currently in use")
        else:
            print("Scanned image has not been deployed to the cluster")
    except:
        print("Warning, cannot check cluster status")
    """
    return p


def scan_all(names):
    results = {
        "UNKNOWN": 0,
        "LOW": 0,
        "MEDIUM": 0,
        "HIGH": 0,
        "CRITICAL": 0,
    }
    results_avg = {}
    results_conv = {}
    results_all = {}
    errors = 0
    for image in names:
        try:
            print(f"checking first image: {image}")
            result = check(image, 'latest')
            print(result)
            results_all[image] = result
            if result[0] == 1:
                results['UNKNOWN'] += 1
            if result[0] == 2:
                results['LOW'] += 1
            if result[0] == 3:
                results['MEDIUM'] += 1
            if result[0] == 4:
                results['HIGH'] += 1
            if result[0] == 5:
                results['CRITICAL'] += 1
            results_avg[image] = result[1]
            results_conv[image] = result[2]
        except Exception as e:
            print(e)
            errors += 1
    print(results)
    print(results_avg)
    print(results_conv)
    print (f'Errors: {errors}')
    print(len(names))

    timestamped = os.getenv('CIPOLICE_TIMESTAMPED_OUTPUT', 'False')
    timestamp = ''
    if timestamped == 'True':
        timestamp = datetime.today().strftime('%Y-%m-%d-')

    output_path = os.getenv('CIPOLICE_OUTPUT_PATH', '.')

    with open(f'{output_path}/{timestamp}max.json', 'w') as f:
        json.dump(results, f, indent=2)
    with open(f'{output_path}/{timestamp}avg.json', 'w') as f:
        json.dump(results_avg, f, indent=2)
    with open(f'{output_path}/{timestamp}conv.json', 'w') as f:
        json.dump(results_conv, f, indent=2)
    return results_all



def check(image, tag):
    result = scan(image, tag)
    tilmax = 0
    tilavg = 0
    summary = Counter()
    count = 0
    if 'Results' in result:
        for res in result['Results']:
            if 'Vulnerabilities' in res:
                for vuln in res['Vulnerabilities']:
                    count += 1
                    if 'CRITICAL' in vuln['Severity']:
                        tilmax = 5 if tilmax <= 5 else tilmax
                        summary['CRITICAL'] += 1
                    elif 'HIGH' in vuln['Severity']:
                        tilmax = 4 if tilmax <= 4 else tilmax
                        summary['HIGH'] += 1
                    elif 'MEDIUM' in vuln['Severity']:
                        tilmax = 3 if tilmax <= 3 else tilmax
                        summary['MEDIUM'] += 1
                    elif 'LOW' in vuln['Severity']:
                        tilmax = 2 if tilmax <= 2 else tilmax
                        summary['LOW'] += 1
                    elif 'UNKNOWN' in vuln['Severity']:
                        tilmax = 1 if tilmax <= 1 else tilmax
                        summary['UNKNOWN'] += 1
    sum = 0
    sum += summary['CRITICAL']*5
    sum += summary['HIGH']*4
    sum += summary['MEDIUM']*3
    sum += summary['LOW']*2
    sum += summary['UNKNOWN']*1

    if count == 0:
        # no vulnarbilites found
        return [0, 0, 0]

    tilavg = sum/count
    print(summary)
    itlconv = min([tilavg + count/50, 5])
    return [tilmax, tilavg, itlconv]


def detail(image, tag):
    result = pull(image, tag)
    print(json.dumps(result['Vulnerabilities'], indent=2))
    with open('output.json', 'w') as f:
        json.dump(result['Vulnerabilities'], f, indent=2)
    choice = input("Manually whitelist image? [y/n]")
    if choice == 'y':
        message = {'image': image, 'override': True}
        requests.post('http://localhost:10080', json=message)
        """
        subprocess.call(f'oc import-image {image}:{tag} --confirm', shell=True)
        b = subprocess.run(f'oc get istag/{image}:{tag} -o json', shell=True, stdout=subprocess.PIPE)
        data = json.loads(b.stdout)
        ref = data['image']['dockerImageReference'].split('@')[1]
        print(ref)
        subprocess.call(f'oc annotate images/{ref} images.openshift.io/deny-execution=false --overwrite --as system:admin', shell=True)
        subprocess.call(f'oc annotate images/{ref} images.openshift.io/timestamp={calendar.timegm(time.gmtime())} --overwrite --as system:admin', shell=True)
        """



if __name__ == '__main__':
    mode = 'http'
    try:
        with open('config.json') as config:
            config_json = json.load(config)
            mode = config_json['mode']
    except:
        mode = 'http'
    if len(sys.argv) < 2:
        print("Usage: scan.py <experiment/pull> <image>")
    else:
        if sys.argv[1] == 'experiment':
            while True:
                #flag = input('This option will use a lot of storage and some data cannot be automatically cleaned up. Continue? [y/n]')
                flag = 'y'
                if flag == 'y':
                    # TODO enable get names again
                    names = get_names()
                    scan_all(names)
                    #cleanup(names)
                    break
                elif flag == 'n':
                    break
        elif sys.argv[1] == 'cluster':
            names = oc_find()
            results = scan_all(names)
            print(results)
            for key, value in results.items():
                if mode == 'rmq':
                    message = f'{{"image": "{key}", "level": {value}}}'
                    print(message)
                    connection = pika.BlockingConnection(pika.ConnectionParameters('localhost'))
                    channel = connection.channel()
                    channel.queue_declare(queue='hello')
                    channel.basic_publish(exchange='',
                                      routing_key='hello',
                                      body=message)
                    connection.close()
                elif mode == 'http':
                    message = {"image": key, "level": value[0], "avg": value[1]}
                    print(message)
                    requests.post('http://localhost:10080', json=message)
        elif sys.argv[1] == 'pull' and len(sys.argv) == 3:
            result = check(sys.argv[2].split(':')[0], sys.argv[2].split(':')[1], 'pull')
            if mode == 'rmq':
                message = f'{{"image": "{sys.argv[2]}", "level": {result}}}'
                print(message)
                connection = pika.BlockingConnection(pika.ConnectionParameters('localhost'))
                channel = connection.channel()
                channel.queue_declare(queue='hello')
                channel.basic_publish(exchange='',
                                  routing_key='hello',
                                  body=message)
                connection.close()
            elif mode == 'http':
                message = {"image": sys.argv[2], "level": result[0], "avg": result[1]}
                print(message)
                requests.post('http://localhost:10080', json=message)
        elif sys.argv[1] == 'push' and len(sys.argv) == 3:
            result = check(sys.argv[2].split(':')[0], sys.argv[2].split(':')[1], 'push')
            if mode == 'rmq':
                message = f'{{"image": "{sys.argv[2]}", "level": {result}}}'
                print(message)
                connection = pika.BlockingConnection(pika.ConnectionParameters('localhost'))
                channel = connection.channel()
                channel.queue_declare(queue='hello')
                channel.basic_publish(exchange='',
                                  routing_key='hello',
                                  body=message)
                connection.close()
            elif mode == 'http':
                message = {"image": sys.argv[2], "level": result[0], "avg": result[1]}
                print(message)
                requests.post('http://localhost:10080', json=message)
        elif sys.argv[1] == 'detail' and len(sys.argv) == 3:
            detail(sys.argv[2].split(':')[0], sys.argv[2].split(':')[1])
        elif sys.argv[1] == 'config' and len(sys.argv) == 2:
            select = input("Press 1 for HTTP mode or 2 for RabbitMQ mode: ")
            with open('config.json', 'w') as config:
                if select == "1":
                    config_json = {"mode": "http"}
                    json.dump(config_json, config)
                elif select == "2":
                    config_json = {"mode": "rmq"}
                    json.dump(config_json, config)


        else:
            print("Usage: scan.py <experiment/pull> <image>")
