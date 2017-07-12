# Fortigate-Rule-Base-Extractor
Extracts the Firewall Rule from Fortigate Firewall configuration file to CSV file

Usage: python ft_rulebase.py -c CONF_FILE -o CSVFILE

If CSVFILE not provided, CSV filename will be same as that of CONF_FILE

Options:
- -h, --help                    show this help message and exit
- -c CONF_FILE, --conf=CONF_FILE  Fortigate Extracted Configuration File
- -o CSVFILE, --output=CSVFILE  Output CSV filename

Report any bugs to [bugs.github@invadersam.com](bugs.github@invadersam.com)
