#!/usr/bin/python

import re, optparse, sys

__author__ = "Sumit Shrivastava"
__version__ = "1.0.0"

config_ver_re = re.compile(r"^#config-version")
policy_start_re = re.compile(r"^config firewall policy")
end_re = re.compile(r"^end")
rule_start_re = re.compile(r"^edit (\d{1,5})")
rule_end_re = re.compile(r"^next")
uuid_re = re.compile(r"^set uuid ([0-9a-f]{8}\-[0-9a-f]{4}\-[0-9a-f]{4}\-[0-9a-f]{4}\-[0-9a-f]{12})")
srcintf_re = re.compile(r"^set srcintf ([\w\d\"\s\-\.]*)")
dstintf_re = re.compile(r"^set dstintf ([\w\d\"\s\-\.]*)")
srcaddr_re = re.compile(r"^set srcaddr ([\w\d\"\s\-\.]*)")
dstaddr_re = re.compile(r"^set dstaddr ([\w\d\"\s\-\.]*)")
action_re = re.compile(r"^set action ([\w\d\"\s\-\.]*)")
schedule_re = re.compile(r"^set schedule ([\w\d\"\s\-\.]*)")
service_re = re.compile(r"^set service ([\w\d\"\s\-\.]*)")
log_traffic_re = re.compile(r"^set logtraffic ([\w\d\"\s\-\.]*)")
comments_re = re.compile(r"^set comments ([\w\d\"\s\-\.#$%@_:;,\/\\\|\(\)\'\!\&'*\^]*)")


def readfile(inputfile):
    firewall_configuration = open(inputfile, "r").readlines()
    print "[+] Read File Complete"
    return firewall_configuration


def extract_rulebase(firewall_configuration=[]):
    firewall_rulebase = []
    counter = 1

    for config_line in firewall_configuration:
        if policy_start_re.match(config_line):
            break
        counter += 1

    for config_line in range(counter, len(firewall_configuration)):
        if end_re.match(firewall_configuration[config_line].strip()):
            break
        firewall_rulebase.append(firewall_configuration[config_line].strip())

    print "[+] Rule Extraction Completed"
    return firewall_rulebase


def parse_rulebase(firewall_rulebase=[]):
    rule_dict = {}
    parameters = {}
    rule_number = ""
    uuid = ""
    source_interface = []
    destination_interface = []
    source_addr = []
    destination_addr = []
    action = ""
    schedule = ""
    service = []
    log_traffic = ""
    comments = ""

    for config_line in firewall_rulebase:
        if rule_start_re.match(config_line):
            rule_number = rule_start_re.match(config_line).groups()[0]

        if uuid_re.match(config_line):
            uuid = uuid_re.match(config_line).groups()[0]

        if srcintf_re.match(config_line):
            sources = srcintf_re.match(config_line).groups()[0]
            interfaces = sources.split("\" \"")
            for interface in interfaces:
                source_interface.append(interface.strip("\""))

        if dstintf_re.match(config_line):
            sources = dstintf_re.match(config_line).groups()[0]
            interfaces = sources.split("\" \"")
            for interface in interfaces:
                destination_interface.append(interface.strip("\""))

        if srcaddr_re.match(config_line):
            addr = srcaddr_re.match(config_line).groups()[0]
            addresses = addr.split("\" \"")
            for address in addresses:
                source_addr.append(address.strip("\""))

        if dstaddr_re.match(config_line):
            addr = dstaddr_re.match(config_line).groups()[0]
            addresses = addr.split("\" \"")
            for address in addresses:
                destination_addr.append(address.strip("\""))

        if action_re.match(config_line):
            action = action_re.match(config_line).groups()[0]

        if schedule_re.match(config_line):
            schedule = schedule_re.match(config_line).groups()[0].strip("\"")

        if service_re.match(config_line):
            key_values = service_re.match(config_line).groups()[0]
            services = key_values.split("\" \"")
            for srv in services:
                service.append(srv.strip("\""))

        if log_traffic_re.match(config_line):
            log_traffic = log_traffic_re.match(config_line).groups()[0].strip("\"")

        if comments_re.match(config_line):
            comments = comments_re.match(config_line).groups()[0].strip("\"")

        if rule_end_re.match(config_line):
            parameters['uuid'] = uuid
            uuid = ""
            parameters['srcintf'] = source_interface
            source_interface = []
            parameters['dstintf'] = destination_interface
            destination_interface = []
            parameters['srcaddr'] = source_addr
            source_addr = []
            parameters['dstaddr'] = destination_addr
            destination_addr = []
            if action == "":
                parameters['action'] = "deny"
            else:
                parameters['action'] = action
            action = ""
            parameters['schedule'] = schedule
            schedule = ""
            parameters['service'] = services
            services = []
            parameters['logtraffic'] = log_traffic
            log_traffic = ""
            parameters['comments'] = comments
            comments = ""
            rule_dict[rule_number] = parameters
            parameters = {}

    print "[+] Rules Parsed :", len(rule_dict.keys())
    return rule_dict


def print_version(firewall_configuration=[]):
    for config_line in firewall_configuration:
        if config_ver_re.match(config_line):
            config_ver, opmode, vdom, user = config_line.split(":")
            print "Configuration Version:", config_ver.split("=")[1]
            print "Operational Mode:", opmode.split("=")[1]
            print "Virtual Domain:", vdom.split("=")[1]
            print "User:", user.split("=")[1].strip()


def write_to_csv(rulebase={}, outputfile=""):
    output_data = "Sr. No.,Rule Number,UUID,Source Interface,Destination Interface,Source Address,Destination Address,Action,Schedule,Service,Log Traffic,Comments\n"
    srno = 1

    for key in rulebase.keys():
        output_data += str(srno) + ","
        output_data += key + ","
        parameters = rulebase[key]
        output_data += parameters['uuid'] + ",\""
        for interface in parameters['srcintf']:
            output_data += interface + ","
        output_data = output_data[:-1:] + "\",\""
        for interface in parameters['dstintf']:
            output_data += interface + ","
        output_data = output_data[:-1:] + "\",\""
        for address in parameters['srcaddr']:
            output_data += address + ","
        output_data = output_data[:-1:] + "\",\""
        for address in parameters['dstaddr']:
            output_data += address + ","
        output_data = output_data[:-1:] + "\","
        output_data += parameters['action'] + ","
        output_data += parameters['schedule'] + ",\""
        for service in parameters['service']:
            output_data += service.strip("\"") + ","
        output_data = output_data[:-1:] + "\","
        output_data += parameters['logtraffic'] + ",\""
        output_data += parameters['comments'] + "\"\n"
        srno+=1

    csvfile = open(outputfile, "w")
    csvfile.write(output_data)
    csvfile.flush()
    csvfile.close()
    print "[+] Output successfully written to", outputfile


def main():
    parser = optparse.OptionParser(
        "python ft_rulebase.py -c CONF_FILE -o CSVFILE\n\r\n\rIf CSVFILE not provided, CSV filename will be same as that of CONF_FILE")
    parser.add_option("-c", "--conf", dest="conf_file", help="Fortigate Extracted Configuration File")
    parser.add_option("-o", "--output", dest="csvfile", help="Output CSV filename")
    options, args = parser.parse_args()
    if not (options.conf_file):
        print "[-] XML file is required"
        parser.print_help()
        print "[-] Program exited with error"
        sys.exit(1)
    else:
        if not (options.csvfile):
            options.csvfile = options.conf_file.split(".")[0] + ".csv"
        else:
            if not (options.csvfile.split(".")[len(options.csvfile.split(".")) - 1] == "csv"):
                options.csvfile = options.csvfile + ".csv"
        write_to_csv(parse_rulebase(extract_rulebase(readfile(options.conf_file))), options.csvfile)
        print "[+] Program completed successfully"


if __name__ == "__main__":
    main()