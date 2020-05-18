import requests
import pika
import json
import subprocess
import sys
import find
import calendar
import time


def get_names():
    link = 'https://hub.docker.com/v2/repositories/library/'
    names = []
    while True:
        data = json.loads(requests.get(link).text)
        if data['next'] is None:
            break
        link = data['next']
        for item in data['results']:
            names.append(item['name'])
    print(names)
    return names


def cleanup(names):
    for image in names:
        subprocess.call(f'docker rmi {image}', shell=True)


def oc_find():
    b = subprocess.run('oc get all -o json', shell=True, stdout=subprocess.PIPE)
    return find.extract_values(json.loads(b.stdout), 'image')


def push(image, tag):
    subprocess.call(f'docker tag {image} localhost:5000/{image}-test', shell=True)
    subprocess.call(f'docker push localhost:5000/{image}-test', shell=True)
    p = subprocess.run(f'CLAIR_ADDR=http://localhost:6060 CLAIR_THRESHOLD=10 REGISTRY_INSECURE=TRUE JSON_OUTPUT=TRUE klar localhost:5000/{image}-test', shell=True, stdout=subprocess.PIPE)
    return json.loads(p.stdout)


def pull(image, tag):
    subprocess.call(f'docker pull {image}:{tag}', shell=True)
    p = push(image, tag)
    try:
        images = oc_find()
        if f'{image}:{tag}' in images:
            print(f"Warning, image {image} is currently in use")
        else:
            print("Scanned image has not been deployed to the cluster")
    except:
        print("Warning, cannot check cluster status")
    return p


def scan_all(names):
    results = {
        "Unknown": 0,
        "Negligible": 0,
        "Low": 0,
        "Medium": 0,
        "High": 0,
        "Critical": 0,
        "Defcon1": 0
    }
    results_avg = {}
    errors = 0
    for image in names:
        try:
            result = check(image, 'latest','pull')
            if result[0] == 1:
                results['Unknown'] += 1
            if result[0] == 2:
                results['Negligible'] += 1
            if result[0] == 3:
                results['Low'] += 1
            if result[0] == 4:
                results['Medium'] += 1
            if result[0] == 5:
                results['High'] += 1
            if result[0] == 6:
                results['Critical'] += 1
            if result[0] == 7:
                results['Defcon1'] += 1
            results_avg[image] = result[1]
        except:
            errors += 1
    print(results)
    print(results_avg)
    print (f'Errors: {errors}')
    print(len(names))



def check(image, tag, mode):
    if mode == 'pull':
        result = pull(image, tag)
    elif mode == 'push':
        result = push(image, tag)
    tilmax = 0
    tilavg = 0
    if 'Defcon1' in result['Vulnerabilities']:
        tilmax = 7
    elif 'Critical' in result['Vulnerabilities']:
        tilmax = 6
    elif 'High' in result['Vulnerabilities']:
        tilmax = 5
    elif 'Medium' in result['Vulnerabilities']:
        tilmax = 4
    elif 'Low' in result['Vulnerabilities']:
        tilmax = 3
    elif 'Negligible' in result['Vulnerabilities']:
        tilmax = 2
    elif 'Unknown' in result['Vulnerabilities']:
        tilmax = 1
    else:
        tilmax = 0
    sum = 0
    count = 0
    if 'Defcon1' in result['Vulnerabilities']:
        sum += len(result['Vulnerabilities']['Defcon1'])*7
        count += len(result['Vulnerabilities']['Defcon1'])
    if 'Critical' in result['Vulnerabilities']:
        sum += len(result['Vulnerabilities']['Critical'])*6
        count += len(result['Vulnerabilities']['Critical'])
    if 'High' in result['Vulnerabilities']:
        sum += len(result['Vulnerabilities']['High'])*5
        count += len(result['Vulnerabilities']['High'])
    if 'Medium' in result['Vulnerabilities']:
        sum += len(result['Vulnerabilities']['Medium'])*4
        count += len(result['Vulnerabilities']['Medium'])
    if 'Low' in result['Vulnerabilities']:
        sum += len(result['Vulnerabilities']['Low'])*3
        count += len(result['Vulnerabilities']['Low'])
    if 'Negligible' in result['Vulnerabilities']:
        sum += len(result['Vulnerabilities']['Negligible'])*2
        count += len(result['Vulnerabilities']['Negligible'])
    if 'Unknown' in result['Vulnerabilities']:
        sum += len(result['Vulnerabilities']['Unknown'])
        count += len(result['Vulnerabilities']['Unknown'])
    tilavg = sum/count
    return [tilmax, tilavg]


def detail(image, tag):
    result = pull(image, tag)
    print(json.dumps(result['Vulnerabilities'], indent=2))
    with open('output.json', 'w') as f:
        json.dump(result['Vulnerabilities'], f, indent=2)
    choice = input("Manually whitelist image? [y/n]")
    if choice == 'y':
        subprocess.call(f'oc import-image {image}:{tag} --confirm', shell=True)
        b = subprocess.run(f'oc get istag/{image}:{tag} -o json', shell=True, stdout=subprocess.PIPE)
        data = json.loads(b.stdout)
        ref = data['image']['dockerImageReference'].split('@')[1]
        print(ref)
        subprocess.call(f'oc annotate images/{ref} images.openshift.io/deny-execution=false --overwrite --as system:admin', shell=True)
        subprocess.call(f'oc annotate images/{ref} images.openshift.io/timestamp={calendar.timegm(time.gmtime())} --overwrite --as system:admin', shell=True)



if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: scan.py <experiment/pull> <image>")
    else:
        if sys.argv[1] == 'experiment':
            while True:
                flag = input('This option will use a lot of storage and some data cannot be automatically cleaned up. Continue? [y/n]')
                if flag == 'y':
                    names = get_names()
                    scan_all(names)
                    cleanup(names)
                    break
                elif flag == 'n':
                    break
        elif sys.argv[1] == 'cluster':
            names = oc_find()
            scan_all(names)
        elif sys.argv[1] == 'pull' and len(sys.argv) == 3:
            result = check(sys.argv[2].split(':')[0], sys.argv[2].split(':')[1], 'pull')
            """
            message = f'{{"image": "{sys.argv[2]}", "level": {result}}}'
            print(message)
            connection = pika.BlockingConnection(pika.ConnectionParameters('localhost'))
            channel = connection.channel()
            channel.queue_declare(queue='hello')
            channel.basic_publish(exchange='',
                              routing_key='hello',
                              body=message)
            connection.close()
            """
            message = {"image": sys.argv[2], "level": result[0], "avg": result[1]}
            print(message)
            #requests.post('http://localhost:10080', json=message)
        elif sys.argv[1] == 'push' and len(sys.argv) == 3:
            result = check(sys.argv[2].split(':')[0], sys.argv[2].split(':')[1], 'push')
            """
            message = f'{{"image": "{sys.argv[2]}", "level": {result}}}'
            print(message)
            connection = pika.BlockingConnection(pika.ConnectionParameters('localhost'))
            channel = connection.channel()
            channel.queue_declare(queue='hello')
            channel.basic_publish(exchange='',
                              routing_key='hello',
                              body=message)
            connection.close()
            """
            message = {"image": sys.argv[2], "level": result[0], "avg": result[1]}
            print(message)
            #requests.post('http://localhost:10080', json=message)
        elif sys.argv[1] == 'detail' and len(sys.argv) == 3:
            detail(sys.argv[2].split(':')[0], sys.argv[2].split(':')[1])


        else:
            print("Usage: scan.py <experiment/pull> <image>")
