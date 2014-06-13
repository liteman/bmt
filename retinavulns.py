'''
Version 1.2

Script for comparison of vulnerability export reports from Retina Security Scanner

Author: liteman,  Blue Mantle Technology

usage:  retina_compare.py compare xmlFile1 xmlFile2
        retina_compare.py report xmlFile1 [-u False]

'''

import sys
import os
import argparse
import xml.etree.ElementTree as ET

VERSION = "1.2"
# Create element tree out of xml file and return the root object
def getTreeRoot(xmlFile):
    try:
        tree = ET.parse(xmlFile)
    except IOError, message:
        print message
        sys.exit(1)
    return tree.getroot()



## Function to build a string containing job data
## Job Name, File Name, Scanner Version, IP, DNS Name
def getMetaData(xmlFile):

    root = getTreeRoot(xmlFile)
    metrics = root.find('metrics')

    #Print Retina Version and Defs File

    print " RTD File: \t", metrics.find('fileName').text.split("\\")[-1]
    print " Scan Date: \t", metrics.find('start').text
    print " IP Range: \t", metrics.find('ipRanges').text
    print " Retina Vers: \t", metrics.find('scannerVersion').text
    print " Audits Rev: \t", metrics.find('auditsRevision').text

## Define a function to list all hosts included in a scan
def listHosts(xmlFile):

    root = getTreeRoot(xmlFile)
    hosts = root.find('hosts')

    # Format the output with appropriate spacing and aligntment
    # Example output should look like this:
    # NetBIOS Name        IP Address          DNS Name
    # ------------        ----------          --------
    # MAINE               192.168.10.100      Maine
    # N/A                 192.168.10.101      unknown

    tableArray = [ ("NetBIOS Name", "IP Address", "DNS Name"),
                 ("-"*12, "-"*10, "-"*8) ]

    # Collect data from the XML file and add tuples to the tableArray
    for host in hosts.iter('host'):
        tableArray.append( (host.find('netBIOSName').text, host.find('ip').text, host.find('dnsName').text) )

    # Define the template for string display.
    displayTemplate = "{0:20}{1:16}{2:20}"

    #Output the headers and line dividers
    print " " + displayTemplate.format(*tableArray[0])
    print " " + displayTemplate.format(*tableArray[1])

    #Loop through the data array starting at item 2 and print the data
    #using the specified format template
    for tup in tableArray[2:]:
        print " " + displayTemplate.format(*tup)

## Define a function to print the severity breakdown
def printSevs(file1, file2, uniq):

    if (uniq == 'True'):
        origSevDict = sevCounts(file1, total=False)
        compSevDict = sevCounts(file2, total=False)
    else:
        origSevDict = sevCounts(file1, uniq=False, total=False)
        compSevDict = sevCounts(file2, uniq=False, total=False)

    print "\nSeverity Breakdown:\n"
    print "\t\t\t", "Baseline", "\t", "Comparison"
    for key in sorted(origSevDict.keys()):
        print " " + key, "\t", str(origSevDict.get(key)).rjust(4), "\t\t", str(compSevDict.get(key)).rjust(4)


## Define a function to show differences between file1 and file2
## Return a dict containing all IDs and Names of findings that ARE in file 1
## but NOT in file2
def diffs(file1, file2):
    result = {}
    dictL1 = {}
    dictL2 = {}

    #Find the roots of each xml structure
    rootOne = getTreeRoot(file1)
    rootTwo = getTreeRoot(file2)

    #Locate the hosts from each XML structure
    hostsOne = rootOne.find('hosts')
    hostsTwo = rootTwo.find('hosts')

    #iterate through the first hosts list and for each host, iterate through
    # the audits. If the audit has a name, add the ID/Name as a key,value
    # pair to dictL1
    for host in hostsOne.iter('host'):
        for audit in host.iter('audit'):
            if audit.find('name').text is not None:
                dictL1[audit.find('rthID').text] = audit.find('name').text

    # iterate through the second hosts list and for each host, iterate through
    # the audits. If the audit has a name, add the ID/Name as a key,value
    # pair to dictL2
    for host in hostsTwo.iter('host'):
        for audit in host.iter('audit'):
            if audit.find('name').text is not None:
                dictL2[audit.find('rthID').text] = audit.find('name').text

    #iterate through the key,value pairs of dictL1
    #if an item does not exist on dictL2, then
    #add the key/value pair to result dict
    for tup in dictL1.items():
        if tup[0] not in dictL2:
            result[tup[0]] = tup[1]

    return result

## Define a function to collect print unique audit id-name combos
def printIDs(xmlFile):

    root = getTreeRoot(xmlFile)
    hosts = root.find('hosts')
    tempDict = {}

    #Create the headers for the list
    tableArray = [ ("Audit ID", "Severity", "Audit Name"),
                 ("-"*8, "-"*8, "-"*10) ]

    #Fill the table with appropriate values  Audit ID, Severity, and Audit Name
    for host in hosts.iter('host'):
        for audit in host.iter('audit'):
        #to be added to the table, the audit must have a name, and ID and it cannot already exist in tempDict
            if audit.find('name').text is not None and audit.find('rthID').text not in tempDict and audit.find('rthID') is not None:
                tempDict[audit.find('rthID').text] = audit.find('name').text  #add to tempDict to prevent duplicates
                tableArray.append( (audit.find('rthID').text, audit.find('sevCode').text, audit.find('name').text) ) #add to the table

    #define the display template with specified field widths
    displayTemplate = "{0:10}{1:15}{2:20}"

    #Output the headers and line dividers
    print " " + displayTemplate.format(*tableArray[0])
    print " " + displayTemplate.format(*tableArray[1])

    #Loop through the data array starting at item 2 and print the data
    #using the specified format template
    #Sort by the second element in the tuples (Severity)
    for tup in sorted(tableArray[2:], key=lambda x: x[1]):
        print " " + displayTemplate.format(*tup)

## Define a function to count findings by sevCode
## default is to return severity counts for unique Audits.
## if uniq is set to False, severity counts will be
## counted for all hosts
## if total is False, return a dict containg the Severity Breakdown
## if total is True, sum the total number of findings
def sevCounts(xmlFile, uniq=True, total=True, breakdown=False):

    #Dict where key is unique Severity Code and values are
    #the counts of each respective Severity Code
    sevCodesDict = { }

    #Temporary Dict where key is unique audit id and value is
    #the respective severity code.
    #This is necessary for cases where multiple hosts were scanned.
    #Multiple hosts adds the potential for duplicate audit
    #IDs. Duplicate audit IDs will skew Severity Counts
    uniqAuditDict = { }

    root = getTreeRoot(xmlFile)
    hosts = root.find('hosts')

    if uniq is True: #only count audit IDs once, regardless of how many hosts are affected

        #Fill uniqAuditDict with unique audit IDs and sevCodes
        for host in hosts.iter('host'):
            for audit in host.iter('audit'):
                rthID = audit.find('rthID').text
                sevCode = audit.find('sevCode').text
                if rthID not in uniqAuditDict:
                    uniqAuditDict[rthID] = sevCode

        #Fill sevCodesDict with counts of each unique severity code
        for audit in uniqAuditDict.items():
            if audit[1] in sevCodesDict:     #if sevCode is already in list, increment counter
              sevCodesDict[audit[1]] += 1
            else:                            #otherwise add sevCode and set value to 1
              sevCodesDict[audit[1]] = 1

        if None in sevCodesDict:
            sevCodesDict.pop(None)            # remove the key where no Severity Code was found "None"

    elif breakdown is True:
    # count audit IDs per host
    # this will require a dictionary where key=IP address and value is an embedded
    # dictionary where key is severity (i.e Category I) and value is count of Severity
    # Example:
    #               hostDict Key:           VALUE
    #                     |      |    ipKey     : Value |
    # hostDict = { "192.168.1.1": {"Category I":"24"} }

        hostDict = {}
        for host in hosts.iter('host'):     # for each host found in the RTD file
            ipAddr = host.find('ip').text   # save the IP address
            hostDict[ipAddr] = {}           # with the IP as the key, set the value to an empty dict
            for audit in host.iter('audit'): # for each audit under that particular host
                sevCode = audit.find('sevCode').text  # save the sevCode
                if sevCode not in hostDict[ipAddr]:
                  hostDict[ipAddr][sevCode] = 1       # if the sevCode key has not been added, add it with a value of 1
                else:
                  hostDict[ipAddr][sevCode] += 1      # if the sevCode key already exists, increment the value

        if None in hostDict[ipAddr]:  hostDict[ipAddr].pop(None)
        return hostDict   # return the populated host dictionary

    else: # count audit IDs as many times as they appear
        for host in hosts.iter('host'):
            for audit in host.iter('audit'):
                sevCode = audit.find('sevCode').text
                if sevCode in sevCodesDict:   # if sevCode is already in list, increment counter
                    sevCodesDict[sevCode] += 1
                else:                         # otherwise add sevCode and set value to 1
                    sevCodesDict[sevCode] = 1

        if None in sevCodesDict:
            sevCodesDict.pop(None)            # remove the key where no Severity Code was found "None"

    if(total):
        count = 0
        # add up all the findings
        for value in sevCodesDict.values():
            count += value
        return count         # int value with total number of findings
    else:
        return sevCodesDict  # dict with severity counts

#Compares output from two XML files and generates appropriate
#reports
def retCompare(args):

    origFile = args.file[0]
    compFile = args.file[1]

    print "\n"
    print "Baseline File Properties"
    getMetaData(origFile)

    print "\n"
    print "Comparison File Properties"
    getMetaData(compFile)

    if (args.uniq == 'True'):
        print "\n"
        print " Unique Findings in baseline: ", sevCounts(origFile)
        print " Unique Findings in comparison: ", sevCounts(compFile)
    else:
        print "\n"
        print " Total Findings in baseline: ", sevCounts(origFile, uniq=False)
        print " Total Findings in comparison: ", sevCounts(compFile,uniq=False)

    #Print a severity breakdown
    #the first argument is considered the baseline
    printSevs(origFile, compFile, args.uniq)

    #Print resolved items. Findings from the baseline which are NOT
    # found on the comparison
    print "\n"
    print "On baseline, but not comparison (Resolved?):\n"
    resolvedDict = diffs(origFile, compFile)  # diffs() returns a dictionary where audit ID is the key
    if resolvedDict:  #if the dict is not empty (True)
        for key in sorted(resolvedDict, key=int): #the keys are audit ids in string format. Sort them as integers
            print "\t", key, ":\t", resolvedDict[key]
    else:
        print "\tNone."

    #Print new items, Findings from the comparison which are NOT
    # found on the baseline
    print "\n"
    print "On comparison, but not baseline (New findings?):\n"

    newFindingsDict = diffs(compFile, origFile) # diffs() returns a dictionary where audit ID is the key
    if newFindingsDict: #if the dict is not empty (True)
        for key in sorted(newFindingsDict, key=int): #the keys are audit ids in string format. Sort them as integers
            print "\t", key, ":\t", newFindingsDict[key]
    else:
        print "\tNone."

    sys.exit(0)

# Display summary of results for the single file specified
def retReport(args):
    ### In Progress

    xmlFile = args.file[0]

    #Print RTD file details
    getMetaData(xmlFile)




    if (args.uniq == 'True'):  #print distinct results
        print "\n"
        print " Distinct Findings: ", sevCounts(xmlFile)

        print "\n"
        print " Severity Breakdown:"
        print " -------------------"
        for item in sorted(sevCounts(xmlFile).items(), total=False):
            print " " + item[0], "\t", str(item[1]).rjust(4)

        print "\n"
        listHosts(xmlFile)

        print "\n"
        printIDs(xmlFile)

    else:                       #print aggregated results
        print "\n"
        print " Total Findings: ", sevCounts(xmlFile, uniq=False)

        print "\n"
        print " Severity Breakdown:"
        print " -------------------"
        for item in sorted(sevCounts(xmlFile, uniq=False).items()):
            print " " + item[0], "\t", str(item[1]).rjust(4)

        print "\n"
        listHosts(xmlFile)

        print "\n"
        print " Breakdown by Host"
        print " -----------------"
        for key, value in sorted(sevCounts(xmlFile,uniq=False, total=False, breakdown=True).items()):
            print "\n ", key, "\n"
            for sev in sorted(value):
                print " \t", sev, "\t", value[sev]



    sys.exit(0)

def main():

    os.system("cls")
    print "\n", " Retina Result Comparison Script -- Version", VERSION
    print "\n"
    parser = argparse.ArgumentParser(description="Compare Retina output", add_help=True)
    subparsers = parser.add_subparsers()

    # Provide command-line option to compare two files
    parser_compare = subparsers.add_parser('compare')
    parser_compare.add_argument('file', nargs=2, help='File path to XML report')
    parser_compare.add_argument('-u', '--uniq', metavar='True/False', default='True', help='Count vulns once per report[True] or once per host [False]')
    parser_compare.set_defaults(func=retCompare)

    # Provide command-line option to report findings from one file
    parser_report = subparsers.add_parser('report')
    parser_report.add_argument('file', nargs=1, help='File path to XML report')
    parser_report.add_argument('-u', '--uniq', metavar='True/False', default='True', help='Count vulns once per report[True] or once per host [False]')
    parser_report.set_defaults(func=retReport)

    # Parse the arguments and call whatever function is selected by
    # the command-line arguments
    args = parser.parse_args()
    args.func(args)


# This is the standard boilerplate that calls the main() function.
if __name__ == '__main__':
  main()