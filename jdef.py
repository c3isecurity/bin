#!/usr/bin/python

print "\n Basic Junos OVAL Content Creator."
print "Copyright (c) 2013, C3isecurity."
print "All rights reserved."
print "version 0.1.8\n"

# The program creates a basic, very simple, OVAL defintion content based on 
# the Open Vulnerability Assessment Lanaguage (OVAL) specifications. It is 
# part of the Security Content Automation Protocol (SCAP).  The program 
# builds a XML defintion file for Juniper Junos.

# import for date and time
import datetime
import time
# import for argument
from sys import argv

# Date and timestamp of defintion 
now = datetime.datetime.now()
def_timestamp = now.strftime("%Y-%m-%dT%H:%M:%S")
def_timestamp_line = "\t\t\t\t<submitted date=\"%s\">\n" % def_timestamp
oval_timestamp = now.strftime("%Y-%m-%dT%H:%M:%S")
oval_timestamp_line = " <oval:timestamp>%s</oval:timestamp>\n" % oval_timestamp

#script, filename = argv
# Write to file name filename.xml
target = open ("filename.xml", 'w')

# Defintion creation.  Input need to create defintion.
# input def_id used the definition number
# INPUT needs to global 

print "Definition ID:"
def_id = raw_input("> ")
def_id_line = "<definition class=\"compliance\" id=\"oval:com.c3isecurity.dev:def:%s\" version=\"0\">\n" % def_id

# input Def Title
print "\nDefinition Title:"
def_title = raw_input("> ")
def_title_line = "\t\t<title>%s</title>\n" % def_title

# input Def_CCE ref_id
print "\nCCE ID:"
def_CCE_ref = raw_input("> ")
def_CCE_ref_line = "\t\t<reference ref_id=\"%s\" ref_url=\"http://www.c3isecurity.com/home/junos-hardening\" source=\"CCE\"/>\n" % def_CCE_ref

# input Definition Comment
print "\nDescription"
def_description = raw_input("> ")
def_description_line = "\t\t<description>%s</description>\n" % def_description

# input comment
print "\nComment:"
def_comment = raw_input("> ")
def_comment_line = "\t\t<criterion comment=\"%s\" test_ref=\"oval:com.c3isecurity.dev:tst:%s\"/>\n" % (def_comment, def_id)

# - - - - - -  Functions - - - - - - - #
def preamble ():
	# XML file preamble function
	target.write("<?xml version=\"1\" encoding=\"UTF-8\"?>\n")
	target.write("""<oval_definitions xmlns=\"http://oval.mitre.org/XMLSchema/oval-definitions-5\"
	  xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"
	  xmlns:oval=\"http://oval.mitre.org/XMLSchema/oval-common-5\"
	  xmlns:oval-def=\"http://oval.mitre.org/XMLSchema/oval-definitions-5\"
	  xmlns:netconf-def=\"http://oval.mitre.org/XMLSchema/oval-definitions-5#netconf\"
	  xsi:schemaLocation=\"http://oval.mitre.org/XMLSchema/oval-definitions-5#netconf netconf-definitions-schema.xsd\">\n""")
	target.write("""  <generator>    
	  <oval:product_name>Juniper Junos OVAL Creator</oval:product_name>
	  <oval:schema_version>5.10</oval:schema_version>\n """) 
	target.write(oval_timestamp_line)
	target.write("  </generator>\n")
	
def definition ():
	#-----------DEFINITION function----------------#
	target.write("<definitions>\n")
	target.write(def_id_line)
	target.write("\t<metadata>\n")
	target.write(def_title_line)
	target.write("\t\t<affected family=\"junos\">\n")
	target.write("\t\t\t<product>Juniper JUNOS</product>\n")
	target.write("\t\t</affected>\n")
	target.write(def_CCE_ref_line)
	target.write(def_description_line)
	target.write("\t\t<oval_repository>\n")
	target.write("\t\t\t<dates>\n")
	target.write(def_timestamp_line)
	target.write("\t\t\t\t<contributor organization=\"C3isecurity\">Luis Nunez</contributor>\n")
	target.write("\t\t\t\t</submitted>\n")
	target.write("\t\t\t</dates>\n")
	target.write("\t\t\t<status>INITIAL SUBMISSION</status>\n")
	target.write("\t\t</oval_repository>\n")
	target.write("\t</metadata>\n")
	target.write("\t<criteria operator=\"AND\">\n")
	target.write(def_comment_line)
	target.write("\t</criteria>\n")
	target.write("</definition>\n")
	target.write("</definitions>\n")
	#-----------DEFINITIONS----------------#
def def_test():
	target.write("<tests>\n")
	config_test_line = "\t<config_test xmlns=\"http://oval.mitre.org/XMLSchema/oval-definitions-5#netconf\" check=\"at least one\" check_existence=\"at_least_one_exists\" comment=\"%s\" id=\"oval:com.c3isecurity.dev:tst:%s\" version=\"0\">\n" % (def_comment, def_id)
	target.write(config_test_line)
	object_ref_line = "\t\t<object object_ref=\"oval:com.c3isecurity:obj:%s\"/>" % def_id
	target.write("\t</config_test>\n")
	target.write("</tests>\n")

def def_objects ():
	config_object_line = "<config_object xmlns=\"http://oval.mitre.org/XMLSchema/oval-definitions-5#netconf\" comment=\"%s\" id=\"oval:org.c3isecurity.oval:obj:%s\" version=\"0\">" % (def_comment, def_id)
	target.write(config_object_line)
	# input Xpath 
	print "\nXpath of command"
	xpath_location = raw_input("> ")
	xpath_location_line = "\t\t<xpath>%s</xpath>\n" % xpath_location
	          #<xpath>//protocols/ospf/area/interface/authentication/md5/key/text()</xpath>
	target.write(xpath_location_line)
	target.write("</config_object>\n")

def def_state ():
	target.write("<states>")
	config_state_line = "\t<config_state xmlns=\"http://oval.mitre.org/XMLSchema/oval-definitions-5#netconf\" comment=\"%s\" id=\"oval:com.c3isecurity.dev:ste:%s\" version=\"0\">" % (def_comment, def_id)
	target.write(config_state_line)
	# input value 
	print "\nValue: "
	state_value = raw_input("> ")
	state_value_line = "\t\t<value_of datatype=\"string\" operation=\"pattern match\"\">%s</value_of>\n" % state_value
	target.write(state_value_line)
	target.write("\t\t</config_state>\n")
	target.write("\t</states>\n")             
	
def def_rearmatter():
	target.write("</oval_definitions>")

# - - - Start writing to file - - -  #
preamble ()
definition ()
def_test ()
def_objects ()
def_state ()
def_rearmatter()

# Close file
target.close()

# Open filename.xml
def_file = open("filename.xml")

# Print the contents of file
print "\n"
print "-------------------------------------------"
print "Contents of file\n"
print def_file.read()
print "--------------------------------------------"
