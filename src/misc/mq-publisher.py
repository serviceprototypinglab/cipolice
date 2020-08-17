# Send a test message in format expected by "clair.rules"
# i.e. run afterwards: python3 cipolice.py -mr clair.rules

import pika

message = '{"image": "nginx:latest", "level": 3}'

connection = pika.BlockingConnection(pika.ConnectionParameters("localhost"))
channel = connection.channel()
channel.queue_declare(queue="hello")
channel.basic_publish(exchange="", routing_key="hello", body=message)
connection.close()

print("Published image scan message", message)
