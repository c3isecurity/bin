#!/bin/sh

# This is a wrapper script

RHrepo="http://www.redhat.com/security/data/data/com.redhat.rhsa-all.xml"

echo "Staring SCAN"
date
# Download content from Red Hat
wget -N $RHrepo -a wgethistory.log -q

report="$(date | awk '{print $2$3$6}')"
ovalresults="$report-oval-results.xml"
ovalreport="$report-oval-report.html"

oscap oval eval --results $ovalresults --report $ovalreport $RHrepo

echo "Created $ovalresults file"
echo "Created $ovalreport file"

echo "End of Script" 