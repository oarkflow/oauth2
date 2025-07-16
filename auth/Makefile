cert:
	openssl req -x509 -newkey rsa:2048 \
	-sha256 \
	-nodes \
	-keyout server.key \
	-out server.crt \
	-days 365 \
	-config san.cnf \
	-extensions req_ext
