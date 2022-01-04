# Fuzz Automata

This is a seed-based random network fuzzer. This tool is intended to be used for IoT devices rather than web serivces.
No protocol specification is required to perform fuzzing against various protocols, but actual packets as seeds need to be collected in advance. 

# Prerequisite

    $ sudo apt install python3-pip nmap
    $ pip3 install --upgrade pip setuptools wheel
    $ pip3 install -r requirements.txt

# Usage

First, collect packets to a target using MITM, then generate a seeds file as below. The target's ip address needs to be specified.

    $ python3 ./fuzz_automata.py -pcap in.pcap -out seeds.json -ip x.x.x.x

Merge seeds files if there are multiple files.

    $ python3 ./fuzz_automata.py -out seeds.json [-minimize] -merge seed1.json [seed2.json ...]

Finally, perform fuzzing. You can also leave HTTP fuzzing to a proxy, like ZAP.

    $ python3 ./fuzz_automata.py -fuzz seeds.json -ip x.x.x.x [-port #] [-proto tcp|udp] [-pileup #] [-proxy x.x.x.x:#]

A log file (yyyymmdd-hhmmss.log) is generated per fuzzing and it can be used for replaying. With '-binsearch' option you can search for the payload that causes hang-up.

    $ python3 ./fuzz-automata.py -replay fuzz.log -ip x.x.x.x [-binsearch]

With '-log2sh' option you can generate a portable shell scipt from a log file.

    $ python3 ./fuzz-automata.py -log2sh fuzz.log -out poc.sh