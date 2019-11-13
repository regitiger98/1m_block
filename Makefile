all : netfilter_block

netfilter_block: main.cpp
	g++ -o 1m_block main.cpp -lnetfilter_queue

clean:
	rm -f 1m_block
