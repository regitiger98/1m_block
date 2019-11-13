all : netfilter_block

netfilter_block: main.cpp
	g++ -o netfilter_block main.cpp -lnetfilter_queue

clean:
	rm -f netfilter_block
