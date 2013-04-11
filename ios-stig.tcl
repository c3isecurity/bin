#lnunez@c3isecurity.com

# This script is intentded to verfity that the IOS device is in compliance with
# the DISA Network Infrastructure STIG check-list.

# Usage: tclsh {offline | online | list} config file
# Usage: tclsh ios-stig.tcl {offline | online | list | help} config file
# -- offline               used to scan config file on a unix system with TCL
# -- online (default)      used to scan from a Cisco IOS device with a tcl parser
# -- list                  display all the STIG checks
# -- help                  list this output

#Examples:
#      router# tclsh ios-stig.tcl
#      linux$ tclsh ios-stig.tcl offline config.txt
#      linux$ tclsh list
#      linux$ help

#This script is used to read a config off-line from a Unix system with Tcl.
#Features:
#   - Reads IOS config files offline
#   - Script can run onboard a IOS system online
#   - Outputs standard out and to a file stig_results
#   - Checks config based on STIG Network Infrastructure Checklist Version 8.

#   - Known issues: When checking offine config files be sure the config file is
#     clean of unseen characters.  The parsing could lead to incorrect scans.
#     Use text files instead of .doc, .rft formats.


puts "Cisco IOS STIG SCAN"
puts "Version 0.4"
puts "Copyright (c) 1986-2013 by C3isecurity, Inc.\n"

set input [lindex $argv 0]
set input2 [lindex $argv 1]

switch $input {
    "offline" {
        puts "offline STIG SCANNING"
        #puts "open file"
        set config [open "$input2" r]
        puts "Opening Config file $input2"
        set results [open "$input2.results" w]
         
        while { [gets $config line] >= 0 } {
            set int_out [read $config]
        }
        close $config
    }
    "online" {
        puts "online STIG SCANNING"
        puts [hostname]
        set results [open "stig.results" w]
        set int_out [exec "show running"]
    }
    "list" {
        puts "LIST of STIGs checks support in this script"
        puts " - - - - - - - - - - - - - - - - - - - - - "    
        puts "   - NET0812 NTP peer|server check"
        puts "   - NET0813 NTP authenticate check"
        puts "   - NET0813 NTP authentication-key check"
        puts "   - NET0813 NTP trust-key check"
        puts "   - NET0899 NTP loopback address check"
        puts "   - NET0809 NTP access control check"
        puts "   - NET0340 Login Banner check"
        puts "   - NET0965 TCP Synwait check"
        puts "   - NET0722 service PAD"
        puts "   - NET0724 TCP Keep-Alives Check"
        puts "   - NET1647 SSH version 2 Check"
        puts "   - NET1646 SSH login attempts greater than 3 Check"
        puts "   - NET1645 SSH timeout 60 seconds Check"
        puts "   - NET0600 service password-encryption"
        puts "   - NET0730 finger Check"
        puts "   - NET0720 TCP small server services check"
        puts "   - NET0720 UDP small server services check"
        puts "   - NET0726 Ident check"
        puts "   - NET0770 IP Source Routing check"
        puts "   - NET0781 Gratuitous ARP check"
        puts "   - NET0949 IP CEF check"
        puts "   - NET-IPv6-033 NET0953 IPv6 CEF check"
        puts "   - NET0750 bootp server check"
        puts "   - NET0760 boot network must be disabled Check"
        puts "   - NET0760 service config must be disabled Check"
        puts "   - NET0820 ip domain-lookup check"
        puts "   - NET0902 FTP use loopback Check"
        puts "   - NET0902 TFTP use loopback Check"
        puts "   - NET0899 NTP use loopback Check"
        puts "   - NET0740 HTTPS server disabled Check"
        puts "   - NET0740 HTTPS server disabled Check"
        puts "   - NET0897 authentication (TACACS+) traffic use loopback Check"
        puts "   - NET0897 authentication (RADIUS) traffic use loopback Check"
        puts "   - NET0898 Syslog traffic loopback"
        puts "   - NET0900 SNMP traffic loopback address Check"
        puts "   - NET0430 Two authentication servers"
        puts "   - NET1021 logging host"
        puts "   - NET1070 TFTP used without written approval (use SCP)"
        puts "   - NET-IPV6-025 IPv6 Site Local Unicast Address must not be defined"
        puts "   - NET-IPV6-034 IPv6 Egress Outbound Spoofing Filter"
        puts "   - NET-0950 uRPF strict mode not enabled on egress interface"
        puts "   - NET-0400 OSPF authentication"
        puts "   - NET-0400 OSPF message-digest"
        exit    
    }
    "help" {
        puts "Usage: tclsh ios-stig.tcl {offline | online | list | help} config file"
        puts " -- offline               used to scan config file on a unix system with TCL"
        puts " -- online (default)      used to scan from a Cisco IOS device with a tcl parser"
        puts " -- list                  display all the STIG checks"
        puts " -- help                  list this output\n"
        puts "Examples:"
        puts "      router# tclsh ios-stig.tcl"
        puts "      linux$ tclsh ios-stig.tcl offline config.txt"
        puts "      linux$ tclsh list"
        puts "      linux$ help"
        exit
    }
    default {
        puts "STIG SCANNING"
        puts [hostname]
        set results [open "$input2.results" w]
        puts $results [hostname]
        set int_out [exec "show running"]
    }
}

set total_test 0
set total_pass 0
set total_fail 0

######################################
    puts "+---------------------+"
    puts "Checking NET1645 SSH timeout 60 seconds Check"
    set check ""
#    set int_out [exec "show running linenum full"]
 
   foreach int [regexp -all -line {^\s*(ip ssh time-out 60)} $int_out] {
        if {![string equal $check $int]} {
            if {[info exists ssh_out]} {
                append ssh_out "," $int
            } else {
                set ssh_out $int
            }
            set check $int
  #         puts $int
        }
    }
    if {$int >= 1} {
        puts "PASS NET1645 SSH timeout 60 seconds Check"
        puts $results "PASS NET1645 SSH timeout 60 seconds Check"
        incr total_pass
    } else {
        puts "FAIL NET1645 SSH timeout 60 seconds Check"
        puts "Severity: CAT II"
        puts $results "FAIL NET1645 SSH timeout 60 seconds Check"
        puts $results "Severity: CAT II"
        puts $results "FIX: ip ssh time-out 60"
        incr total_fail
    }
  # puts $ntp_out
   puts "Finished NET1645 SSH timeout 60 seconds Check"
   puts "+---------------------+"
   puts $results "+---------------------+"
   incr total_test
    
    
######################################
    puts "Checking NET1646 SSH login attempts greater than 3 Check"
    set check ""
#    set int_out [exec "show running linenum full"]
   foreach int [regexp -all -line {^\s*(ip ssh authentication-retries 3)} $int_out] {
        if {![string equal $check $int]} {
            if {[info exists ssh_out]} {
                append ssh_out "," $int
            } else {
                set ssh_out $int
            }
            set check $int
  #         puts $int
        }
    }
    if {$int >= 1} {
        puts "PASS NET1646 SSH login attempts greater than 3 Check"
        puts $results "PASS NET1646 SSH login attempts greater than 3 Check"
        incr total_pass
    } else {
        puts "FAIL NET1646 SSH login attempts greater than 3 Check"
        puts "Severity: CAT II"
        puts $results "FAIL NET1646 SSH login attempts greater than 3 Check"
        puts $results "Severity: CAT II"
        puts $results "FIX: ip ssh authentication-retries 3"
        incr total_fail        
    }
  # puts $ntp_out
   puts "Finished NET1646 SSH login attempts greater than 3 Check"
   puts "+---------------------+"
   puts $results "+---------------------+"
   incr total_test
######################################
    puts "Checking NET1647 SSH version 2 Check"
    set check ""
#    set int_out [exec "show running linenum full"]
   foreach int [regexp -all -line {^\s*(ip ssh version 2)} $int_out] {
        if {![string equal $check $int]} {
            if {[info exists ntp_out]} {
                append pad_out "," $int
            } else {
                set pad_out $int
            }
            set check $int
  #         puts $int
        }
    }
    if {$int >= 1} {
        puts "PASS NET1647 SSH version 2 Check"
        puts $results "PASS NET1647 SSH version 2 Check"
        incr total_pass
    } else {
        puts "FAIL NET1647 SSH version 2 Check"
        puts "Severity: CAT II"
        puts $results "FAIL NET1647 SSH version 2 Check"
        puts $results "Severity: CAT II"
        puts $results "FIX: ip ssh version 2"
        incr total_fail        
    }
  # puts $ntp_out
   puts "Finished NET1647 SSH version 2 Check"
   puts "+---------------------+"
   puts $results "+---------------------+"
   incr total_test

######################################

    puts "Checking NET0724 TCP Keep-Alives Check"
    set check ""
#    set int_out [exec "show running linenum full"]
 
   foreach int [regexp -all -line {^\s*(no service pad)} $int_out] {
        if {![string equal $check $int]} {
            if {[info exists ntp_out]} {
                append pad_out "," $int
            } else {
                set pad_out $int
            }
            set check $int
  #         puts $int
        }
    }
    if {$int >= 1} {
        puts "PASS NET0724 TCP Keep-Alives Check"
        puts $results "PASS NET0724 TCP Keep-Alives Check"
        incr total_pass
    } else {
        puts "FAIL NET0724 TCP Keep-Alives Check"
        puts "Severity: CAT III"
        puts $results "FAIL NET0724 TCP Keep-Alives Check"
        puts $results "Severity: CAT II"
        puts $results "FIX: service tcp-keepalives-in"
        incr total_fail
    }
  # puts $ntp_out
   puts "Finished NET0724 TCP Keep-Alives Check"
   puts "+----------------------+"
   puts $results "+---------------------+"
   incr total_test
#######################################
    puts "Checking NET0722 service PAD"
    set check ""
#    set int_out [exec "show running linenum full"]
 
   foreach int [regexp -all -line {^\s*(no service pad)} $int_out] {
        if {![string equal $check $int]} {
            if {[info exists ntp_out]} {
                append pad_out "," $int
            } else {
                set pad_out $int
            }
            set check $int
  #         puts $int
        }
    }
    if {$int >= 1} {
        puts "PASS NET0722 service PAD Check"
        puts $results "PASS NET0722 service PAD Check"
        incr total_pass
    } else {
        puts "FAIL NET0722 no service PAD Check"
        puts "Severity: CAT III"
        puts $results "FAIL NET0722 no service PAD Check"
        puts $results "Severity: CAT III"
        puts $results "FIX: no service pad"
        incr total_fail
    }
  # puts $ntp_out
   puts "Finished NET0722 service PAD Check"
   puts "+----------------------+"
   puts $results "+---------------------+"
   incr total_test
#######################################
    puts "Checking NET0340 Login Banner"
    set check ""
#    set int_out [exec "show running linenum full"]
 
   foreach int [regexp -all -line {^\s*(banner login|banner motd)} $int_out] {
        if {![string equal $check $int]} {
            if {[info exists ntp_out]} {
                append banner_out "," $int
            } else {
                set banner_out $int
            }
            set check $int
  #         puts $int
        }
    }
    if {$int >= 1} {
        puts "PASS NET0340 Login Banner Check"
        puts $results "PASS NET0340 Login Banner Check"
        incr total_pass
    } else {
        puts "FAIL NET0340 Login Banner Check"
        puts "Severity: CAT II"
        puts $results "FAIL NET0340 Login Banner Check"
        puts $results "Severity: CAT II"
        incr total_fail
    }
  # puts $ntp_out
   puts "Finished NET0340 Login Banner Check"
   puts "+----------------------+"
   puts $results "+---------------------+"
   incr total_test
########################################   
    puts "Checking NET0965 TCP Synwait"
    set check ""
#    set int_out [exec "show running linenum full"]
 
   foreach int [regexp -all -line {^\s*(ip tcp synwait-time 10)} $int_out] {
        if {![string equal $check $int]} {
            if {[info exists ntp_out]} {
                append ntp_out "," $int
            } else {
                set ntp_out $int
            }
            set check $int
  #         puts $int
        }
    }
    if {$int >= 1} {
        puts "PASS NET0965 TCP Synwait Check"
        puts $results "PASS NET0965 TCP Synwait Check"
        incr total_pass
    } else {
        puts "FAIL NET0965 TCP Synwait Check"
        puts "Severity: CAT II"
        puts $results "FAIL NET0965 TCP Synwait Check"
        puts $results "Severity: CAT II"
        puts $results "FIX: ip tcp synwait-time 10"
        incr total_fail
    }
  # puts $ntp_out
   puts "Finished NET0965 TCP Synwait Check"
   puts "+----------------------+"
   puts $results "+---------------------+"
   incr total_test   
######################################
    puts "Checking NET0812 NTP server"
    set check ""
#    set int_out [exec "show running linenum full"]
 
    foreach int [regexp -all -line {^\s*(ntp peer|ntp server){1,}} $int_out] {
        if {![string equal $check $int]} {
            if {[info exists ntp_out]} {
                append ntp_out "," $int
            } else {
                set ntp_out $int
            }
            set check $int
  #        puts $int
        }
    }
    if {$int >= 2} {
        puts "PASS NET0812 NTP server/peer Check"
        puts $results "PASS NET0812 NTP server/peer Check"
        incr total_pass
    } else {
        puts "FAIL NET0812 NTP server/peer Check"
        puts "Severity: CAT III"
        puts $results "FAIL NET0812 NTP server/peer Check"
        puts $results "Severity: CAT III"
        incr total_fail
    }
  # puts $ntp_out
   puts "Finished NET0812 server/peer Check"
   puts "+----------------------+"
   puts $results "+---------------------+"
   incr total_test
######################################
    puts "Checking NET0813 NTP authenticate"
    set check ""
#    set int_out [exec "show running linenum full"]
 
    foreach int [regexp -all -line {^\s*(ntp authenticate.*){1,}} $int_out] {
        if {![string equal $check $int]} {
            if {[info exists ntp_out]} {
                append ntp_out "," $int
            } else {
                set ntp_out $int
            }
            set check $int
  #         puts $int
        }
    }
    if {[string equal 1 $int]} {
        puts "PASS NET0813 NTP authenticate Check"
        puts $results "PASS NET0813 NTP authenticate Check"
        incr total_pass
    } else {
        puts "FAIL NET0813 NTP Check"
        puts "Severity: CAT III"
        puts $results "FAIL NET0813 NTP authenticate Check"
        puts $results "Severity: CAT III"
        incr total_fail
    }
  # puts $ntp_out
   puts "Finished NET0813 NTP authenticate Check"
   puts "+----------------------+"
   puts $results "+---------------------+"
   incr total_test
#######################################

    puts "Checking NET0813 NTP authentication-key"
    set check ""
#    set int_out [exec "show running linenum full"]
 
    foreach int [regexp -all -line {^\s*(ntp authentication-key.*){1,}} $int_out] {
        if {![string equal $check $int]} {
            if {[info exists ntp_out]} {
                append ntp_out "," $int
            } else {
                set ntp_out $int
            }
            set check $int
  #         puts $int
        }
    }
    if {[string equal 1 $int]} {
        puts "PASS NET0813 NTP Authentication-key Check"
        puts $results "PASS NET0813 NTP Authentication-key Check"
        incr total_pass
    } else {
        puts "FAIL NET0813 NTP Authentication-key Check"
        puts "Severity: CAT III"
        puts $results "FAIL NET0813 NTP Authentication-key Check"
        puts $results "Severity: CAT III"
        incr total_fail
    }
  # puts $ntp_out
   puts "Finished NET0813 authentication-key Check"
   puts "+----------------------+"
   puts $results "+---------------------+"
   incr total_test
#######################################
    puts "Checking NET0813 NTP trusted-key"
    set check ""
#    set int_out [exec "show running linenum full"]
 
    foreach int [regexp -all -line {^\s*(ntp trusted-key.*){1,}} $int_out] {
        if {![string equal $check $int]} {
            if {[info exists ntp_out]} {
                append ntp_out "," $int
   #             puts one
            } else {
                set ntp_out $int
            }
            set check $int
  #         puts $int
        }
    }
    if {[string equal 1 $int]} {
        puts "PASS NET0813 NTP Trusted-key Check"
        puts $results "PASS NET0813 NTP Trusted-key Check"
        incr total_pass
    } else {
        puts "FAIL NET0813 NTP Trusted-key Check"
        puts "Severity: CAT III"
        puts $results "FAIL NET0813 NTP Trusted-key Check"
        puts $results "Severity: CAT III"
        incr total_fail
    }
  # puts $ntp_out
   puts "Finished NET0813 NTP Trusted-key Check"
   puts "+----------------------+"
   puts $results "+---------------------+"
   incr total_test
#######################################
    puts "Checking NET0899 NTP loopback address"
    set check ""
#    set int_out [exec "show running linenum full"]
 
   foreach int [regexp -all -line {^\s*(ntp source Loopback.*){1,}} $int_out] {
        if {![string equal $check $int]} {
            if {[info exists ntp_out]} {
                append ntp_out "," $int
            } else {
                set ntp_out $int
            }
            set check $int
  #         puts $int
        }
    }
    if {[string equal 1 $int]} {
        puts "PASS NET0899 NTP Loopback Check"
        puts $results "PASS NET0899 NTP Loopback Check"
        incr total_pass
    } else {
        puts "FAIL NET0899 NTP Loopback Check"
        puts "Severity: CAT III"
        puts $results "FAIL NET0899 NTP Loopback Check"
        puts $results "Severity: CAT III"
        incr total_fail
    }
  # puts $ntp_out
   puts "Finished NET0899 NTP Loopback Check"
   puts "+----------------------+"
   puts $results "+---------------------+"
   incr total_test
#######################################
# Deprecated from the STIG
#    puts "Checking NET0809 NTP access control"
#    set check ""
#    set int_out [exec "show running linenum full"]
 
#   foreach int [regexp -all -line {^\s*(ntp access-group peer|ntp access-group query-only|ntp access-group serve|ntp access-group serve-only){1,}} $int_out] {
#        if {![string equal $check $int]} {
#            if {[info exists ntp_out]} {
#                append ntp_out "," $int
#            } else {
#                set ntp_out $int
#            }
#            set check $int
  #         puts $int
#        }
#    }
#    if {[string equal 1 $int]} {
#        puts "PASS NET0809 NTP access control Check"
#        puts $results "PASS NET0809 NTP access control Check"
#        incr total_pass
#    } else {
#        puts "FAIL NET0809 NTP access control Check"
#        puts "Severity: CAT III"
#        puts $results "FAIL NET0809 NTP access control Check"
#        puts $results "Severity: CAT III"
#        incr total_fail
#    }
  # puts $ntp_out
#   puts "Finished NET0809 NTP access control Check"
#   puts"+----------------------+"
#   puts $results "+---------------------+"
#   incr total_test
#######################################
    puts "Checking NET0730 finger Check"
    set check ""
#    set int_out [exec "show running linenum full"]
 
   foreach int [regexp -all -line {^\s*(ip finger)} $int_out] {
        if {![string equal $check $int]} {
            if {[info exists finger_out]} {
                append finger_out "," $int
            } else {
                set finger_out $int
            }
            set check $int
  #         puts $int
        }
    }
    if {$int >= 1} {
        puts "FAIL NET0730 finger Check"
        puts "Severity: CAT III"
        puts $results "FAIL NET0730 finger Check"
        puts $results "Severity: CAT III"
        puts $results "FIX: no finger service"
        incr total_fail        
    } else {
        puts "PASS NET0730 finger Check"
        puts $results "PASS NET0730 finger Check"
        incr total_pass
    }
   puts "Finished NET0730 finger Check"
   puts "+----------------------+"
   puts $results "+---------------------+"    
   incr total_test
######################################
    puts "Checking NET0600 service password-encryption check"
    set check ""
#    set int_out [exec "show running linenum full"]
 
   foreach int [regexp -all -line {^\s*(service password-encryption)} $int_out] {
        if {![string equal $check $int]} {
            if {[info exists ep_out]} {
                append epp_out "," $int
            } else {
                set ep_out $int
            }
            set check $int
  #         puts $int
        }
    }
    if {[string equal 1 $int]} {
        puts "PASS NET0600 service password-encryption check"
        puts $results "PASS NET0600 service password-encryption check"
        incr total_pass
    } else {
        puts "FAIL NET0600 service password-encryption check"
        puts "Severity: CAT I"
        puts $results "FAIL NET0600 service password-encryption check"
        puts $results "Severity: CAT I"
        puts $results "service password-encryption"
        incr total_fail
    }
   puts "Finished NET0600 service password-encryption check"
   puts "+----------------------+"
   puts $results "+---------------------+"
   incr total_test
#######################################
    puts "Checking NET0720 TCP small server services check"
    set check ""
#    set int_out [exec "show running linenum full"]
 
   foreach int [regexp -all -line {^\s*(service tcp-small-servers)} $int_out] {
        if {![string equal $check $int]} {
            if {[info exists tcpsmall_out]} {
                append tcpsmall_out "," $int
            } else {
                set tcpsmall_out $int
            }
            set check $int
  #         puts $int
        }
    }
    if {[string equal 1 $int]} {
        puts "FAIL NET0720 TCP small server services check"
        puts "Severity: CAT III"
        puts $results "FAIL NET0720 TCP small server services check"
        puts $results "Severity: CAT III"
        puts $results "no service tcp-small-servers"
        incr total_fail        
    } else {
        puts "PASS NET0720 TCP small server services check"
        puts $results "PASS NET0720 TCP small server services check"
        incr total_pass        
    }
   puts "Finished NET0720 TCP small server services check"
   puts "+----------------------+"
   puts $results "+---------------------+"
   incr total_test
#######################################
    puts "Checking NET0720 UDP small server services check"
    set check ""
#    set int_out [exec "show running linenum full"]
 
   foreach int [regexp -all -line {^\s*(service udp-small-servers)} $int_out] {
        if {![string equal $check $int]} {
            if {[info exists udpsmall_out]} {
                append udpsmall_out "," $int
            } else {
                set udpsmall_out $int
            }
            set check $int
        }
    }
    if {[string equal 1 $int]} {
        puts "FAIL NET0720 UDP small server services check"
        puts "Severity: CAT III"
        puts $results "FAIL NET0720 UDP small server services check"
        puts $results "Severity: CAT III"
        puts $results "no service udp-small-servers"
        incr total_fail        
    } else {
        puts "PASS NET0720 UDP small server services check"
        puts $results "PASS NET0720 UDP small server services check"
        incr total_pass
    }
   puts "Finished NET0720 UDP small server services check"
   puts "+----------------------+"
   puts $results "+---------------------+"
   incr total_test
#######################################
    puts "Checking NET0726 Ident check"
    set check ""
#    set int_out [exec "show running linenum full"]
 
   foreach int [regexp -all -line {^\s*(ip ident)} $int_out] {
        if {![string equal $check $int]} {
            if {[info exists ident_out]} {
                append ident_out "," $int
            } else {
                set idnet_out $int
            }
            set check $int
        }
    }
    if {[string equal 1 $int]} {
        puts "FAIL NET0726 Ident check"
        puts "Severity: CAT III"
        puts $results "FAIL NET0726 Ident check"
        puts $results "Severity: CAT III"
        puts $results "no ip ident"
        incr total_fail        
    } else {
        puts "PASS NET0726 Ident check"
        puts $results "PASS NET0726 Ident check"
        incr total_pass
    }
   puts "Finished NET0726 Ident check"
   puts "+----------------------+"
   puts $results "+---------------------+"
   incr total_test
#######################################
    puts "Checking NET0770 IP Source Routing"
    set check ""
#    set int_out [exec "show running linenum full"]
 
    foreach int [regexp -all -line {^\s*(no ip source-route)} $int_out] {
        if {![string equal $check $int]} {
            if {[info exists sr_out]} {
                append sr_out "," $int
            } else {
                set sr_out $int
            }
            set check $int
  #        puts $int
        }
    }
    if {$int >= 1} {
        puts "PASS NET0770 IP Source Routing Check"
        puts $results "PASS NET0770 IP Source Routing Check"
        incr total_pass
    } else {
        puts "FAIL NET0770 IP Source Routing Check"
        puts "Severity: CAT III"
        puts $results "FAIL NET0770 IP Source Routing Check"
        puts $results "Severity: CAT II"
        puts $results "no ip source-route"
        incr total_fail
    }
  # puts $ntp_out
   puts "Finished NET0770 IP Source Routing Check"
   puts "+----------------------+"
   puts $results "+---------------------+"
   incr total_test
######################################
    puts "Checking NET0781 Gratuitous ARP"
    set check ""
#    set int_out [exec "show running linenum full"]
 
    foreach int [regexp -all -line {^\s*(no ip gratuitous-arps)} $int_out] {
        if {![string equal $check $int]} {
            if {[info exists sr_out]} {
                append sr_out "," $int
            } else {
                set sr_out $int
            }
            set check $int
  #        puts $int
        }
    }
    if {$int >= 1} {
        puts "PASS NET0781 Gratuitous ARP Check"
        puts $results "PASS NET0781 Gratuitous ARP Check"
        incr total_pass
    } else {
        puts "FAIL NET0781 Gratuitous ARP Check"
        puts "Severity: CAT III"
        puts $results "FAIL NET0781 Gratuitous ARP Check"
        puts $results "Severity: CAT II"
        puts $results "no ip gratuitous-arps"
        incr total_fail
    }
  # puts $ntp_out
   puts "Finished NET0781 Gratuitous ARP Check"
   puts "+----------------------+"
   puts $results "+---------------------+"
   incr total_test
######################################
    puts "Checking NET0949 IP CEF"
    set check ""
#    set int_out [exec "show running linenum full"]
 
    foreach int [regexp -all -line {^\s*(ip cef)} $int_out] {
        if {![string equal $check $int]} {
            if {[info exists cef_out]} {
                append cef_out "," $int
            } else {
                set cef_out $int
            }
            set check $int
  #        puts $int
        }
    }
    if {$int >= 1} {
        puts "PASS NET0949 IP CEF Check"
        puts $results "PASS NET0949 IP CEF Check"
        incr total_pass
    } else {
        puts "FAIL NET0949 IP CEF Check"
        puts "Severity: CAT II"
        puts $results "FAIL NET0949 IP CEF Check"
        puts $results "Severity: CAT II"
        puts $results "FIX: ip cef"
        incr total_fail
    }
  # puts $ntp_out
   puts "Finished NET0949 IP CEF Check"
   puts "+----------------------+"
   puts $results "+---------------------+"
   incr total_test
######################################
   puts "Checking NET-IPV6-033 IPv6 CEF"
    set check ""
#    set int_out [exec "show running linenum full"]
 
    foreach int [regexp -all -line {^\s*(ipv6 cef)} $int_out] {
        if {![string equal $check $int]} {
            if {[info exists cef_out]} {
                append cef_out "," $int
            } else {
                set cef_out $int
            }
            set check $int
  #        puts $int
        }
    }
    if {$int >= 1} {
        puts "PASS NET-IPV6-033 IPv6 CEF Check"
        puts $results "PASS NET-IPV6-033 IPv6 CEF Check"
        incr total_pass
    } else {
        puts "FAIL NET-IPV6-033 IPv6 CEF Check"
        puts "Severity: CAT II"
        puts $results "FAIL NET-IPV6-033 IPv6 CEF Check"
        puts $results "Severity: CAT II"
        puts $results "FIX: ipv6 cef"
        incr total_fail
    }
  # puts $ntp_out
   puts "Finished NET-IPV6-033 IPv6 CEF Check"
   puts "+----------------------+"
   puts $results "+---------------------+"
   incr total_test
######################################
   puts "Checking NET0750 bootp server"
    set check ""
#    set int_out [exec "show running linenum full"]
 
    foreach int [regexp -all -line {^\s*(no ip bootp server)} $int_out] {
        if {![string equal $check $int]} {
            if {[info exists cef_out]} {
                append cef_out "," $int
            } else {
                set cef_out $int
            }
            set check $int
  #        puts $int
        }
    }
    if {$int >= 1} {
        puts "PASS NET0750 bootp server Check"
        puts $results "PASS NET0750 bootp server Check"
        incr total_pass
    } else {
        puts "FAIL NET0750 bootp server Check"
        puts "Severity: CAT II"
        puts $results "FAIL NET0750 bootp server Check"
        puts $results "Severity: CAT II"
        puts $results "FIX: no ip bootp server"
        incr total_fail
    }
  # puts $ntp_out
   puts "Finished NET0750 bootp server Check"
   puts "+----------------------+"
   puts $results "+---------------------+"
   incr total_test
######################################
   puts "Checking NET0760 boot network must be disabled"
    set check ""
#    set int_out [exec "show running linenum full"]
 
    foreach int [regexp -all -line {^\s*(boot network)} $int_out] {
        if {![string equal $check $int]} {
            if {[info exists cef_out]} {
                append cef_out "," $int
            } else {
                set cef_out $int
            }
            set check $int
  #        puts $int
        }
    }
    if {$int >= 1} {
        puts "FAIL NET0760 boot network must be disabled Check"
        puts "Severity: CAT II"
        puts $results "FAIL NET0760 boot network must be disabled Check"
        puts $results "Severity: CAT II"
        puts $results "FIX: no boot network"
        incr total_fail        
    } else {
        puts "PASS NET0760 boot network must be disabled Check"
        puts $results "PASS NET0750 boot network must be disabled Check"
        incr total_pass
    }
  # puts $ntp_out
   puts "Finished NET0760 boot network must be disabled Check"
   puts "+----------------------+"
   puts $results "+---------------------+"
   incr total_test
######################################
   puts "Checking NET0760 service config must be disabled"
    set check ""
#    set int_out [exec "show running linenum full"]
 
    foreach int [regexp -all -line {^\s*(service config)} $int_out] {
        if {![string equal $check $int]} {
            if {[info exists cef_out]} {
                append cef_out "," $int
            } else {
                set cef_out $int
            }
            set check $int
  #        puts $int
        }
    }
    if {$int >= 1} {
        puts "FAIL NET0760 service config must be disabled Check"
        puts "Severity: CAT II"
        puts $results "FAIL NET0760 service config must be disabled Check"
        puts $results "Severity: CAT II"
        puts $results "FIX: no service config"
        incr total_fail        
    } else {
        puts "PASS NET0760 service config must be disabled Check"
        puts $results "PASS NET0750 service config must be disabled Check"
        incr total_pass
    }
  # puts $ntp_out
   puts "Finished NET0760 service config must be disabled Check"
   puts "+----------------------+"
   puts $results "+---------------------+"
   incr total_test
######################################
  puts "Checking NET0820 ip domain-lookup"
    set check ""
#    set int_out [exec "show running linenum full"]
# logic if "no ip domain-lookup" or "ip name-server" exists its a pass.
    foreach int [regexp -all -line {^\s*(no ip domain-lookup|ip name-server)} $int_out] {
        if {![string equal $check $int]} {
            if {[info exists cef_out]} {
                append cef_out "," $int
            } else {
                set cef_out $int
            }
            set check $int
  #        puts $int
        }
    }
    if {$int >= 1} {
        puts "PASS NET0820 ip domain-lookup Check"
        puts $results "PASS NET0820 ip domain-lookup Check"
        incr total_pass
    } else {
        puts "FAIL NET0820 ip domain-lookup Check"
        puts "Severity: CAT II"
        puts $results "FAIL NET0820 ip domain-lookup Check"
        puts $results "Severity: CAT II"
        puts $results "FIX: no ip domain-lookup"
        incr total_fail
    }
  # puts $ntp_out
   puts "Finished NET0820 ip domain-lookup Check"
   puts "+----------------------+"
   puts $results "+---------------------+"
   incr total_test
######################################
  puts "Checking NET0902 FTP use loopback"
    set check ""
#    set int_out [exec "show running linenum full"]
    foreach int [regexp -all -line {^\s*(ip ftp source-interface Loopback)} $int_out] {
        if {![string equal $check $int]} {
            if {[info exists cef_out]} {
                append cef_out "," $int
            } else {
                set cef_out $int
            }
            set check $int
  #        puts $int
        }
    }
    if {$int >= 1} {
        puts "PASS NET0902 FTP use loopback Check"
        puts $results "PASS NET0902 FTP use loopback Check"
        incr total_pass
    } else {
        puts "FAIL NET0902 FTP use loopback Check"
        puts "Severity: CAT III"
        puts $results "FAIL NET0902 FTP use loopback Check"
        puts $results "Severity: CAT III"
        puts $results "FIX: ip ftp source-interface Loopback0"
        incr total_fail
    }
  # puts $ntp_out
   puts "Finished NET0902 FTP use loopback Check"
   puts "+----------------------+"
   puts $results "+---------------------+"
   incr total_test
######################################
  puts "Checking NET0902 TFTP use loopback"
    set check ""
#    set int_out [exec "show running linenum full"]
    foreach int [regexp -all -line {^\s*(ip tftp source-interface Loopback)} $int_out] {
        if {![string equal $check $int]} {
            if {[info exists cef_out]} {
                append cef_out "," $int
            } else {
                set cef_out $int
            }
            set check $int
  #        puts $int
        }
    }
    if {$int >= 1} {
        puts "PASS NET0902 TFTP use loopback Check"
        puts $results "PASS NET0902 TFTP use loopback Check"
        incr total_pass
    } else {
        puts "FAIL NET0902 TFTP use loopback Check"
        puts "Severity: CAT III"
        puts $results "FAIL NET0902 TFTP use loopback Check"
        puts $results "Severity: CAT III"
        puts $results "FIX: ip tftp source-interface Loopback0"
        incr total_fail
    }
  # puts $ntp_out
   puts "Finished NET0902 TFTP use loopback Check"
   puts "+----------------------+"
   puts $results "+---------------------+"
   incr total_test
######################################
  puts "Checking NET0899 NTP use loopback"
    set check ""
#    set int_out [exec "show running linenum full"]
    foreach int [regexp -all -line {^\s*(ntp source Loopback)} $int_out] {
        if {![string equal $check $int]} {
            if {[info exists cef_out]} {
                append cef_out "," $int
            } else {
                set cef_out $int
            }
            set check $int
  #        puts $int
        }
    }
    if {$int >= 1} {
        puts "PASS NET0899 NTP use loopback Check"
        puts $results "PASS NET0899 NTP use loopback Check"
        incr total_pass
    } else {
        puts "FAIL NET0899 NTP use loopback Check"
        puts "Severity: CAT III"
        puts $results "FAIL NET0899 NTP use loopback Check"
        puts $results "Severity: CAT III"
        puts $results "FIX: ntp source Loopback0"
        incr total_fail
    }
  # puts $ntp_out
   puts "Finished NET0899 NTP use loopback Check"
   puts "+----------------------+"
   puts $results "+---------------------+"
   incr total_test
######################################
  puts "Checking NET0740 HTTP server disabled"
    set check ""
#    set int_out [exec "show running linenum full"]
    foreach int [regexp -all -line {^\s*(no ip http server)} $int_out] {
        if {![string equal $check $int]} {
            if {[info exists cef_out]} {
                append cef_out "," $int
            } else {
                set cef_out $int
            }
            set check $int
  #        puts $int
        }
    }
    if {$int >= 1} {
        puts "PASS NET0740 HTTP server disabled Check"
        puts $results "PASS NET0740 HTTP server disabled Check"
        incr total_pass
    } else {
        puts "FAIL NET0740 HTTP server disabled Check"
        puts "Severity: CAT II"
        puts $results "FAIL NET0740 HTTP server disabled Check"
        puts $results "Severity: CAT II"
        puts $results "FIX: no ip http server"
        incr total_fail
    }
  # puts $ntp_out
   puts "Finished NET0740 HTTP server disabled Check"
   puts "+----------------------+"
   puts $results "+---------------------+"
   incr total_test
######################################
  puts "Checking NET0740 HTTPS server disabled"
    set check ""
#    set int_out [exec "show running linenum full"]
    foreach int [regexp -all -line {^\s*(no ip http secure-server)} $int_out] {
        if {![string equal $check $int]} {
            if {[info exists cef_out]} {
                append cef_out "," $int
            } else {
                set cef_out $int
            }
            set check $int
  #        puts $int
        }
    }
    if {$int >= 1} {
        puts "PASS NET0740 HTTPS server disabled Check"
        puts $results "PASS NET0740 HTTPS server disabled Check"
        incr total_pass
    } else {
        puts "FAIL NET0740 HTTPS server disabled Check"
        puts "Severity: CAT II"
        puts $results "FAIL NET0740 HTTPS server disabled Check"
        puts $results "Severity: CAT II"
        puts $results "FIX: no ip http secure-server"
        incr total_fail
    }
  # puts $ntp_out
   puts "Finished NET0740 HTTPS server disabled Check"
   puts "+----------------------+"
   puts $results "+---------------------+"
   incr total_test
######################################
  puts "Checking NET0897 authentication (TACACS+) traffic use loopback"
    set check ""
#    set int_out [exec "show running linenum full"]
    foreach int [regexp -all -line {^\s*(ip tacacs source-interface Loopback)} $int_out] {
        if {![string equal $check $int]} {
            if {[info exists cef_out]} {
                append cef_out "," $int
            } else {
                set cef_out $int
            }
            set check $int
  #        puts $int
        }
    }
    if {$int >= 1} {
        puts "PASS NET0897 authentication (TACACS+) traffic use loopback Check"
        puts $results "PASS NET0897 authentication (TACACS+) traffic use loopback Check"
        incr total_pass
    } else {
        puts "FAIL NET0897 authentication (TACACS+) traffic use loopback Check"
        puts "Severity: CAT III"
        puts $results "FAIL NET0897 authentication (TACACS+) traffic use loopback Check"
        puts $results "Severity: CAT III"
        puts $results "FIX: ip tacacs source-interface Loopback"
        incr total_fail
    }
  # puts $ntp_out
   puts "Finished NET0897 authentication (TACACS+) traffic use loopback Check"
   puts "+----------------------+"
   puts $results "+---------------------+"
   incr total_test
######################################
  puts "Checking NET0897 authentication (RADIUS) traffic use loopback"
    set check ""
#    set int_out [exec "show running linenum full"]
    foreach int [regexp -all -line {^\s*(ip radius source-interface Loopback)} $int_out] {
        if {![string equal $check $int]} {
            if {[info exists cef_out]} {
                append cef_out "," $int
            } else {
                set cef_out $int
            }
            set check $int
  #        puts $int
        }
    }
    if {$int >= 1} {
        puts "PASS NET0897 authentication (RADIUS) traffic use loopback Check"
        puts $results "PASS NET0897 authentication (RADIUS) traffic use loopback Check"
        incr total_pass
    } else {
        puts "FAIL NET0897 authentication (RADIUS) traffic use loopback Check"
        puts "Severity: CAT III"
        puts $results "FAIL NET0897 authentication (RADIUS) traffic use loopback Check"
        puts $results "Severity: CAT III"
        puts $results "FIX: ip radius source-interface Loopback"
        incr total_fail
    }
  # puts $ntp_out
   puts "Finished NET0897 authentication (RADIUS) traffic use loopback Check"
   puts "+----------------------+"
   puts $results "+---------------------+"
   incr total_test
######################################
  puts "Checking NET0898 Syslog traffic loopback"
    set check ""
#    set int_out [exec "show running linenum full"]
    foreach int [regexp -all -line {^\s*(logging source-interface Loopback)} $int_out] {
        if {![string equal $check $int]} {
            if {[info exists cef_out]} {
                append cef_out "," $int
            } else {
                set cef_out $int
            }
            set check $int
  #        puts $int
        }
    }
    if {$int >= 1} {
        puts "PASS NET0898 Syslog traffic loopback Check"
        puts $results "PASS NET0898 Syslog traffic loopback Check"
        incr total_pass
    } else {
        puts "FAIL NET0898 Syslog traffic loopbackCheck"
        puts "Severity: CAT III"
        puts $results "FAIL NET0898 Syslog traffic loopback Check"
        puts $results "Severity: CAT III"
        puts $results "FIX: logging source-interface Loopback"
        incr total_fail
    }
  # puts $ntp_out
   puts "Finished NET0898 Syslog traffic loopback Check"
   puts "+----------------------+"
   puts $results "+---------------------+"
   incr total_test
######################################
  puts "Checking NET0900 SNMP traffic loopback address"
    set check ""
#    set int_out [exec "show running linenum full"]
    foreach int [regexp -all -line {^\s*(snmp-server trap-source Loopback)} $int_out] {
        if {![string equal $check $int]} {
            if {[info exists cef_out]} {
                append cef_out "," $int
            } else {
                set cef_out $int
            }
            set check $int
  #        puts $int 
        }
    }
    if {$int >= 1} {
        puts "PASS NET0900 SNMP traffic loopback address Check"
        puts $results "PASS NET0900 SNMP traffic loopback address Check"
        incr total_pass
    } else {
        puts "FAIL NET0900 SNMP traffic loopback address Check"
        puts "Severity: CAT III"
        puts $results "FAIL NET0900 SNMP traffic loopback address Check"
        puts $results "Severity: CAT III"
        puts $results "FIX: snmp-server trap-source Loopback"
        incr total_fail
    }
  # puts $ntp_out
   puts "Finished NET0900 SNMP traffic loopback address Check"
   puts "+----------------------+"
   puts $results "+---------------------+"
   incr total_test
######################################
  puts "Checking NET0430 Two authentication servers"
    set check ""
#    set int_out [exec "show running linenum full"]
    foreach int [regexp -all -line {^\s*(tacacs-server host)} $int_out] {
        if {![string equal $check $int]} {
            if {[info exists cef_out]} {
                append cef_out "," $int
            } else {
                set cef_out $int
            }
            set check $int
  #        puts $int
        }
    }
    if {$int >= 2} {
        puts "PASS NET0430 Two authentication servers Check"
        puts $results "PASS NET0430 Two authentication servers Check"
        incr total_pass
    } else {
        puts "FAIL NET0430 Two authentication servers Check"
        puts "Severity: CAT II"
        puts $results "FAIL NET0430 Two authentication servers Check"
        puts $results "Severity: CAT II"
        puts $results "FIX: tacacs-server host"
        incr total_fail
    }
  # puts $ntp_out
   puts "Finished NET0430 Two authentication servers Check"
   puts "+----------------------+"
   puts $results "+---------------------+"
   incr total_test
######################################
  puts "Checking NET1021 logging host"
    set check ""
#    set int_out [exec "show running linenum full"]
    foreach int [regexp -all -line {^\s*(logging host)} $int_out] {
        if {![string equal $check $int]} {
            if {[info exists cef_out]} {
                append cef_out "," $int
            } else {
                set cef_out $int
            }
            set check $int
  #        puts $int
        }
    }
    if {$int >= 2} {
        puts "PASS NET1021 logging host Check"
        puts $results "PASS NET1021 logging host Check"
        incr total_pass
    } else {
        puts "FAIL NET1021 logging host Check"
        puts "Severity: CAT III"
        puts $results "FAIL NET1021 logging host Check"
        puts $results "Severity: CAT III"
        puts $results "FIX: logging host"
        incr total_fail
    }
  # puts $ntp_out
   puts "Finished NET1021 logging host Check"
   puts "+---------------------+"
   puts $results "+---------------------+"
   incr total_test
######################################
  puts "Checking NET1070 SCP"
#------- Intnet of the STIG item is to use SCP instead of tftp.
# NET1070 The IAO/NSO will authorize and maintain justification
# for all TFTP implementations.   
#------- Reference Network Policy STIG for further details
    set check ""
    foreach int [regexp -all -line {^\s*(ip scp server enable)} $int_out] {
        if {![string equal $check $int]} {
            if {[info exists scp_out]} {
                append scp_out "," $int
            } else {
                set scp_out $int
            }
            set check $int
  #        puts $int 
        }
    }
    if {$int >= 1} {
        puts "PASS NET1070 SCP Check"
        puts $results "PASS NET1070 SCP Check"
        incr total_pass
    } else {
        puts "FAIL NET1070 SCP Check"
        puts "Severity: CAT III"
        puts $results "FAIL NET1070 SCP Check"
        puts $results "Severity: CAT III"
        puts $results "FIX: ip scp server enable"
        incr total_fail
    }
   puts "Finished NET1070 SCP Check"
   puts "+------------------------+"
   puts $results "+---------------------+"
   incr total_test
######################################
  puts "Checking NET-IPV6-025 IPv6 Site Local Unicast Address must not be defined"
    set check ""
#    set int_out [exec "show running linenum full"]
# logic if "no ip domain-lookup" or "ip name-server" exists its a pass.
    foreach int [regexp -all -line {^\s*(ipv6 address FEC|ipv6 address FED|ipv6 address FEE|ipv6 address FEF)} $int_out] {
        if {![string equal $check $int]} {
            if {[info exists site_local_out]} {
                append site_local_out "," $int
            } else {
                set site_local_out $int
            }
            set check $int
  #        puts $int
        }
    }
    if {$int >= 1} {
        puts "FAIL NET-IPV6-025 IPv6 Site Local Unicast Address Check"
        puts "Severity: CAT II"
        puts $results "FAIL NET-IPV6-025 IPv6 Site Local Unicast Address Check"
        puts $results "Severity: CAT II"
        puts $results "FIX: no ipv6 address"
        incr total_fail
    } else {
        puts "PASS NET-IPV6-025 IPv6 Site Local Unicast Address"
        puts $results "PASSNET-IPV6-025 IPv6 Site Local Unicast Address Check"
        incr total_pass
    }
  # puts $ntp_out
   puts "Finished NET-IPV6-025 IPv6 Site Local Unicast Address Check"
   puts "+------------------------+"
   puts $results "+------------------------+"
   incr total_test

######################################
    puts "Checking NET-0950 uRPF strict mode not enabled on egress interface"
    set check ""
#    set int_out [exec "show running linenum full"]
#   Reference the Network Perimeter Router Checklist 
    foreach int [regexp -all -line {^\s*(ip verify unicast source reachable-via rx)} $int_out] {
        if {![string equal $check $int]} {
            if {[info exists test1_out]} {
                append test1_out "," $int
            } else {
                set test_out1 $int
            }
            set check $int
        }
    }
    if {$int >= 1} {
        puts "PASS NET-0950 uRPF strict mode not enabled on egress interface Check"
        puts $results "PASS NNET-0950 uRPF strict mode not enabled on egress interface Check"
        incr total_pass
    } else {
        puts "FAIL NET-0950 uRPF strict mode not enabled on egress interface Check"
        puts "Severity: CAT I"
        puts $results "FAIL NET-0950 uRPF strict mode not enabled on egress interface Check"
        puts $results "Severity: CAT I"
        puts $results "FIX: ipv6 verfiy unicast source reachable-via rx"
        incr total_fail
    }
   puts "Finished NET-0950 uRPF strict mode not enabled on egress interface Check"
   puts "+------------------------+"
   puts $results "+------------------------+"
   incr total_test     
######################################
    puts "Checking NET-IPV6-034 IPv6 Egress Outbound Spoofing Filter"
    set check ""
#    set int_out [exec "show running linenum full"]
#   Reference the Network Perimeter Router Checklist
 
    foreach int [regexp -all -line {^\s*(ipv6 verfiy unicast source reachable-via rx)} $int_out] {
        if {![string equal $check $int]} {
            if {[info exists test1_out]} {
                append test1_out "," $int
            } else {
                set test_out1 $int
            }
            set check $int
        }
    }
    if {$int >= 1} {
        puts "PASS NET-IPV6-034 IPv6 Egress Outbound Spoofing Filter Check"
        puts $results "PASS NET-IPV6-034 IPv6 Egress Outbound Spoofing Filter Check"
        incr total_pass
    } else {
        puts "FAIL NET-IPV6-034 IPv6 Egress Outbound Spoofing Filter Check"
        puts "Severity: CAT II"
        puts $results "FAIL NET-IPV6-034 IPv6 Egress Outbound Spoofing Filter Check"
        puts $results "Severity: CAT II"
        puts $results "FIX: ipv6 verfiy unicast source reachable-via rx"
        incr total_fail
    }
   puts "Finished NET-IPV6-034 IPv6 Egress Outbound Spoofing Filter Check"
   puts "+------------------------+"
   puts $results "+------------------------+"
   incr total_test

#####################################
    puts "Checking NET-0400 OSPF authentication"
    set check ""
#    set int_out [exec "show running linenum full"]
#   Reference the Network Perimeter Router Checklist
 
    foreach int [regexp -all -line {\s*(area \d authentication message-digest)} $int_out] {
        if {![string equal $check $int]} {
            if {[info exists test1_out]} {
                append test1_out "," $int
            } else {
                set test_out1 $int
            }
            set check $int
        }
    }
    if {$int >= 1} {
        puts "PASS Checking NET-0400 OSPF authentication Check"
        puts $results "PASS Checking NET-0400 OSPF authentication Check"
        incr total_pass
    } else {
        puts "FAIL Checking NET-0400 OSPF authentication Check"
        puts "Severity: CAT II"
        puts $results "FAIL Checking NET-0400 OSPF authentication Check"
        puts $results "Severity: CAT II"
        puts $results "FIX: area 0 authentication message-digest"
        incr total_fail
    }
   puts "Finished NET-0400 OSPF authentication Check"
   puts "+------------------------+"
   puts $results "+------------------------+"
   incr total_test
#####################################
    puts "Checking NET-0400 OSPF message-digest"
    set check ""
#    set int_out [exec "show running linenum full"]
#   Reference the Network Perimeter Router Checklist
 
    foreach int [regexp -all -line {\s*(ip ospf message-digest)} $int_out] {
        if {![string equal $check $int]} {
            if {[info exists test1_out]} {
                append test1_out "," $int
            } else {
                set test_out1 $int
            }
            set check $int
        }
    }
    if {$int >= 1} {
        puts "PASS Checking NET-0400 OSPF message-digest Check"
        puts $results "PASS CNET-0400 OSPF message-digest Check"
        incr total_pass
    } else {
        puts "FAIL Checking NET-0400 OSPF message-digest Check"
        puts "Severity: CAT II"
        puts $results "FAIL Checking Checking NET Check"
        puts $results "Severity: CAT II"
        puts $results "FIX: ip ospf message-digest 10 md5 mypassword"
        incr total_fail
    }
   puts "Finished NET-0400 OSPF message-digest Check"
   puts "+------------------------+"
   puts $results "+------------------------+"
   incr total_test   
#----------- End Script Body ----------#

puts "STIG SCANNING FINISHED"
set time [clock format [clock seconds]]
puts $time
puts "Total Checked: $total_test"
puts "Total PASS: $total_pass"
puts "Total FAIL: $total_fail"

puts $results "Configuration Hygiene Check"
puts $results $time
puts $results "Total Checked: $total_test"
puts $results "Total PASS: $total_pass"
puts $results "Total FAIL: $total_fail"
puts $results "\n"

close $results
#puts "closed file"
#- - - - - - - End of script - - - - - -#
