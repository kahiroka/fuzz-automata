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

Finally, perform fuzzing.

    $ python3 ./fuzz_automata.py -fuzz seeds.json -ip x.x.x.x [-port #] [-pileup #] [-proxy x.x.x.x:#]

A log file (yyyymmdd-hhmmss.log) is generated per fuzzing and it can be used for replaying.

    $ python3 ./fuzz-automata.py -replay fuzz.log -ip x.x.x.x [-port #]