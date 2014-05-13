#!/bin/sh
# This script will do an OVAL scan.  It first fetches the latest content from oval.mitre.org then runs
# ovaldi

echo "Starting goval script"
wget http://oval.mitre.org/rep-data/5.7/org.mitre.oval/p/platform/ubuntu.12.04.xml -O /home/ubuntu/oval/oval-ubuntu.xml -N

ovaldi -m -o /home/ubuntu/oval/oval-ubuntu.xml 

echo "End goval script"
