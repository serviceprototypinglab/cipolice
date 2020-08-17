flavour=$1

if [ "$flavour" = "example" ]
then
	curl -X POST -d '{"image": "nginx:latest", "cve": "CVE-X"}' http://localhost:10080/
else
	curl -X POST -d '{"image": "nginx:latest", "level": 3}' http://localhost:10080/
fi
