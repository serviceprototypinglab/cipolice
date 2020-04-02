import sys
import subprocess
import docker


client = docker.from_env()


def pull(image):
    return client.images.pull(image)


if __name__ == '__main__':
    image = pull(sys.argv[1])
    print(image.tags)
    status = subprocess.call(f'curl -s -L https://raw.githubusercontent.com/simonsdave/clair-cicd/master/bin/assess-image-risk.sh | bash -s -- {image.tags[0]}', shell=True)
    print(status)
