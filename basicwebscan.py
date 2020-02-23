"""
nmap scan and then run scanners against any web server ports found
"""

import argparse
import collections
import json
import logging
import os
import subprocess


import nmap


ENUMLOG = logging.getLogger('ENUMLOG')
ENUMLOG.setLevel(logging.DEBUG)


class CommandError(Exception):
    """
    raise if there is an error when executing the shell command
    """


class WebScanners():
    """
    run specific web vunerability scanners against a host
    """

    def __init__(self, url, outputdir):
        self.url = url
        self.outputdir = outputdir

    def run_all(self):
        """
        run all scanners
        """
        try:
            self.run_nikto()
            self.run_whatweb()
            self.run_dirb()
        except CommandError:
            ENUMLOG.exception('error running command against %s', self.url)

    def run_nikto(self):
        """
        runs nikto against the target - security checks

        all scripts except denial of service (x6)
        timeout of 4 seconds
        html output
        """
        ENUMLOG.info('running nikto against %s', self.url)
        savelog = os.path.join(self.outputdir, 'nikto.html')
        run_command(['nikto', '-Tuning', 'x6', '-o', savelog, '-Format',
                     'htm', '-timeout', '4', '-h', self.url])

    def run_whatweb(self):
        """
        run whatweb to identify technologies used by the web site
        """
        ENUMLOG.info('running whatweb against %s', self.url)
        savelog = os.path.join(self.outputdir, 'whatweb.txt')
        logargs = '--log-verbose={}'.format(savelog)
        run_command(['whatweb', '-q', '-a', '3', logargs, self.url])
        
    def run_dirb(self):
        """
        run dirb to find hidden web objects, basically do a dictionary attack
        to find out paths on the web server
        """
        ENUMLOG.info('running dirb against %s', self.url)
        savelog = os.path.join(self.outputdir, 'dirb.txt')
        run_command(['dirb', self.url, '/usr/share/wordlists/dirb/small.txt',
                     '-o', savelog, '-S'])


class nmapScanner():
    """class for the nmap scanner"""

    def __init__(self, target, outputdirpath):
        self.target = target
        self.outputdirpath = outputdirpath
        self.webservers = collections.defaultdict(list)

    def initial_scan(self):
        """
        scans all TCP ports

        host discovery options
        -PS SYN ping
        -PA ACK ping
        -PU UDP ping
        -PY SCTP ping
        -PE ICMP ping
        -PR ARP ping
        
        scan options
        -A  aggressive OS & service detection
        -sS SYN scan
        -v verbose
        --max-retries 4
        -T 5 fastest speed
        """
        cliargs = ('-PS -PA -PU -PY -PE -PR -A -sS -T 5 -v -p-'
                   ' --max-retries 4 --open')
        ENUMLOG.info('initial tcp port scan started')
        nmpTCP = nmap.PortScanner()
        scanresults = nmpTCP.scan(
            hosts=self.target,
            arguments=cliargs)
        jsonpath = os.path.join(self.outputdirpath, 'initialTCPscan.json')
        save_json_output(scanresults, jsonpath)
        csvpath = os.path.join(self.outputdirpath, 'initialscan_TCP.csv')
        with open(csvpath, 'w') as csvf:
            csvf.write(nmpTCP.csv())
        ENUMLOG.debug(scanresults['nmap']['command_line'])
        ENUMLOG.info('intial tcp port scan finished')
        return scanresults

    def filter_results(self, scanresults):
        """
        filter results for further enumeration
        """
        ENUMLOG.info('filtering scan results for futher enumeration')
        for host in scanresults['scan']:
            for port in scanresults['scan'][host]['tcp']:
                if scanresults['scan'][host]['tcp'][port]['state'] == 'open':
                    if scanresults['scan'][host]['tcp'][port]['name'] == 'http':
                        self.webservers[host].append(port)

    def enum_http(self):
        """
        scan the webservers we have found
        """
        for webserver in self.webservers:
            for port in self.webservers[webserver]:
                outstr = 'webvunscan-{}-TCP{}'.format(webserver,str(port))
                weboutput = os.path.join(self.outputdirpath, outstr)
                if not os.path.exists(weboutput):
                    os.makedirs(weboutput)
                nmp = nmap.PortScanner()
                httpscheck = nmp.scan(
                    hosts=webserver, arguments='-Pn --script=+ssl-cert',
                    ports=str(port))
                try:
                    https = httpscheck['scan'][webserver]['tcp'][port]['script']
                    ENUMLOG.info('%s port %s is using https',
                                 webserver, str(port))
                    weburl = 'https://{}:{}'.format(webserver, str(port))
                except KeyError:
                    ENUMLOG.info('%s port %s is using http',
                                 webserver, str(port))
                    weburl = 'http://{}:{}'.format(webserver, str(port))
                webvunscan = WebScanners(weburl, weboutput)
                webvunscan.run_all()


def save_json_output(indict, outjsonpath):
    """
    save a python dictionary as json to a file
    
    Args:
        indict(dict): dictionary to save into the JSON file
        outjsonpath(str): full path to save the JSON file to
    """
    with open(outjsonpath, 'w') as jsonf:
        json.dump(indict, jsonf, indent=2)


def run_command(argslist):
    """
    run a shell command and process the result

    Args:
        argslist(list): list of strings of the command and its arguments

    Raises:
        CommandError: exception if there is output to standard error

    Returns:
        completed.stdout(str): the standard output of the command
    """
    completed = subprocess.run(argslist, stderr=subprocess.PIPE,
        stdout=subprocess.PIPE, universal_newlines=True)
    if completed.stderr:
        raise CommandError(completed.stderr)
    else:
        return completed.stdout


def setup_logging(logfilepath):
    """
    setup logging to a file and the terminal
    
    Args:
        logfilepath(str): where to save the log file to
    """
    logfilehandler = logging.FileHandler(
        logfilepath, mode='w')
    logformatter = logging.Formatter(
        fmt='%(asctime)s,%(name)s,%(levelname)s,%(message)s',
        datefmt='%Y/%m/%d,%H:%M:%S')
    logfilehandler.setFormatter(logformatter)
    ENUMLOG.addHandler(logfilehandler)
    terminalhandler = logging.StreamHandler()
    terminalstrformat = '%(asctime)s -  %(message)s'
    terminalformatter = logging.Formatter(
        fmt=terminalstrformat, datefmt='%Y/%m/%d  %H:%M:%S')
    terminalhandler.setFormatter(terminalformatter)
    ENUMLOG.addHandler(terminalhandler)


def main():
    """
    main program code starts here
    """
    parser = argparse.ArgumentParser(
        description='scanning and enumeration script for web pen testing')
    parser.add_argument(dest='target', help='ip to target')
    parser.add_argument(dest='outputdir',
                        help='directory to output results into')
    args = parser.parse_args()
    setup_logging(os.path.join(args.outputdir, 'pentest.log'))
    ENUMLOG.info('started scan of ' + args.target)
    nmapscanner = nmapScanner(args.target, args.outputdir)
    scanresults = nmapscanner.initial_scan()
    nmapscanner.filter_results(scanresults)
    nmapscanner.enum_http()
    ENUMLOG.info('finished')


if __name__ == "__main__":
    main()
