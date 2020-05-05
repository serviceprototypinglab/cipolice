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
            names.append(item['name'])
    print(names)
    return names


def cleanup(names):
    for image in names:
        subprocess.call(f'docker rmi {image}', shell=True)


def scan(image, tag):
    subprocess.call(f'docker pull {image}:{tag}', shell=True)
    subprocess.call(f'docker tag {image} localhost:5000/{image}-test', shell=True)
    subprocess.call(f'docker push localhost:5000/{image}-test', shell=True)
    p = subprocess.run(f'CLAIR_ADDR=http://localhost:6060 CLAIR_THRESHOLD=10 REGISTRY_INSECURE=TRUE JSON_OUTPUT=TRUE klar localhost:5000/{image}-test', shell=True, stdout=subprocess.PIPE)
    try:
        b = subprocess.run('oc get all -o json', shell=True, stdout=subprocess.PIPE)
        images = find.extract_values(json.loads(b.stdout), 'image')
        if f'{image}:{tag}' in images:
            print(f"Warning, image {image} is currently in use")
        else:
            print("Scanned image has not been deployed to the cluster")
    except:
        print("Warning, cannot check cluster status")
    return json.loads(p.stdout)


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
    errors = 0
    for image in names:
        try:
            result = scan(image, 'latest')
            if 'Unknown' in result['Vulnerabilities']:
                results['Unknown'] += 1
            if 'Negligible' in result['Vulnerabilities']:
                results['Negligible'] += 1
            if 'Low' in result['Vulnerabilities']:
                results['Low'] += 1
            if 'Medium' in result['Vulnerabilities']:
                results['Medium'] += 1
            if 'High' in result['Vulnerabilities']:
                results['High'] += 1
            if 'Critical' in result['Vulnerabilities']:
                results['Critical'] += 1
            if 'Defcon1' in result['Vulnerabilities']:
                results['Defcon1'] += 1
        except:
            errors += 1
    print(results)
    print (f'Errors: {errors}')
    print(len(names))


def check(image, tag):
    result = scan(image, tag)
    if 'Defcon1' in result['Vulnerabilities']:
        return 7
    elif 'Critical' in result['Vulnerabilities']:
        return 6
    elif 'High' in result['Vulnerabilities']:
        return 5
    elif 'Medium' in result['Vulnerabilities']:
        return 4
    elif 'Low' in result['Vulnerabilities']:
        return 3
    elif 'Negligible' in result['Vulnerabilities']:
        return 2
    elif 'Unknown' in result['Vulnerabilities']:
        return 1
    else:
        return 0

def detail(image, tag):
    result = scan(image, tag)
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
        elif sys.argv[1] == 'pull' and len(sys.argv) == 3:
            result = check(sys.argv[2].split(':')[0], sys.argv[2].split(':')[1])
            message = f'{{"image": "{sys.argv[2]}", "level": "{result}"}}'
            print(message)
            connection = pika.BlockingConnection(pika.ConnectionParameters('localhost'))
            channel = connection.channel()
            channel.queue_declare(queue='hello')
            channel.basic_publish(exchange='',
                              routing_key='hello',
                              body=message)
            connection.close()
        elif sys.argv[1] == 'detail' and len(sys.argv) == 3:
            detail(sys.argv[2].split(':')[0], sys.argv[2].split(':')[1])


        else:
            print("Usage: scan.py <experiment/pull> <image>")
