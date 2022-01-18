# FuzZ:Automata

This is a seed-based random network fuzzer. This tool is intended to be used for IoT devices rather than web serivces.
No protocol specification is required to perform fuzzing against various protocols, but actual packets as seeds need to be collected in advance. 

# Prerequisite

    $ sudo apt install python3-pip nmap
    $ pip install fuzz-automata-kahiroka

# Usage

First, collect packets to a target using MITM, then generate a seeds file as below. The target's ip address needs to be specified.

    $ fuzz-automata -pcap in.pcap -out seeds.json -ip x.x.x.x [-multicast]

Merge seeds files if there are multiple files.

    $ fuzz-automata -out seeds.json [-minimize] -merge seed1.json [seed2.json ...]

Finally, perform fuzzing. You can also leave HTTP fuzzing to a proxy, like ZAP.

    $ fuzz-automata -fuzz seeds.json -ip x.x.x.x [-port #] [-proto tcp|udp] [-pileup #] [-proxy x.x.x.x:#]

A log file (yyyymmdd-hhmmss-port#.log) is generated per fuzzing and it can be used for replaying later. With '-binsearch' option you can search for the payload(s) that causes hang-up.

    $ fuzz-automata -replay fuzz.log -ip x.x.x.x [-binsearch]

With '-log2sh' option you can generate a portable shell script from a log file.

    $ fuzz-automata -log2sh fuzz.log -out poc.sh

With '-show' option you can see an overview of a seeds file.

    $ fuzz-automata -show seeds.json
