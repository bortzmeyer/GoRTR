all: text-client/text-client

text-client/text-client:
	(cd rtr; go build)
	(cd text-client; go build)

clean:
	rm -f text-client/text-client database-store-client/database-store-client

