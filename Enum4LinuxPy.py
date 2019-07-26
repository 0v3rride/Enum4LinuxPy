#!/usr/bin/env python3

import argparse;
import subprocess;
import datetime;
import terminaltables;
import re;
import sys;
import time;
import random;
from termcolor import cprint;

# Global Vars
dependent_programs = ["nmblookup", "net", "rpcclient", "smbclient"];
optional_dependent_programs = ["polenum", "ldapsearch"];
user_list = [];

###############################################################################
# The following  mappings for nmblookup (nbtstat) status codes to human readable
# format is taken from nbtscan 1.5.1 "statusq.c".  This file in turn
# was derived from the Samba package which contains the following
# license:
#    Unix SMB/Netbios implementation
#    Version 1.9
#    Main SMB server routine
#    Copyright (C) Andrew Tridgell 1992-1999
#
#    This program is free software; you can redistribute it and/or modif
#    it under the terms of the GNU General Public License as published b
#    the Free Software Foundation; either version 2 of the License, o
#    (at your option) any later version
#
#    This program is distributed in the hope that it will be useful
#    but WITHOUT ANY WARRANTY; without even the implied warranty o
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See th
#    GNU General Public License for more details
#
#    You should have received a copy of the GNU General Public Licens
#    along with this program; if not, write to the Free Softwar
#    Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA

# TUPLE BASED DICTIONARY
nbt_info = {
    ("..__MSBROWSE__.", "01"): "Master Browser",
    ("INet~Services", "1c"): "IIS",
    ("IS~", "00"): "IIS",
    ("", "00"): "Workstation Service",
    ("", "01"): "Messenger Service",
    ("", "03"): "Messenger Service",
    ("", "06"): "RAS Server Service",
    ("", "1f"): "NetDDE Service",
    ("", "20"): "File Server Service",
    ("", "21"): "RAS Client Service",
    ("", "22"): "Microsoft Exchange Interchange(MSMail Connector)",
    ("", "23"): "Microsoft Exchange Store",
    ("", "24"): "Microsoft Exchange Directory",
    ("", "30"): "Modem Sharing Server Service",
    ("", "31"): "Modem Sharing Client Service",
    ("", "43"): "SMS Clients Remote Control",
    ("", "44"): "SMS Administrators Remote Control Tool",
    ("", "45"): "SMS Clients Remote Chat",
    ("", "46"): "SMS Clients Remote Transfer",
    ("", "4C"): "DEC Pathworks TCPIP service on Windows NT",
    ("", "52"): "DEC Pathworks TCPIP service on Windows NT",
    ("", "87"): "Microsoft Exchange MTA",
    ("", "6A"): "Microsoft Exchange IMC",
    ("", "Be"): "Network Monitor Agent",
    ("", "Bf"): "Network Monitor Application",
    ("", "03"): "Messenger Service",
    ("", "02"): "Domain/Workgroup Name",
# nbt stat code is really 00, but is 02 to prevent duplication; difference between this and workstation is that Domain/Workgroup Name will have <GROUP> on the same line, workstation will not
    ("", "1b"): "Domain Master Browser",
    ("", "1c"): "Domain Controllers",
    ("", "1d"): "Master Browser",
    ("", "1e"): "Browser Service Elections",
    ("", "2b"): "Lotus Notes Server Service",
    ("IRISMULTICAST", "2f"): "Lotus Notes",
    ("IRISNAMESERVER", "33"): "Lotus Notes",
    ('Forte_$ND800ZA', "20"): "DCA IrmaLan Gateway Server Service"
}


####################### end of nbtscan-derrived code ############################


def setArgs(uargs):
    # check arguments
    if uargs.a:
        uargs.U = True;
        uargs.S = True;
        uargs.G = True;
        uargs.r = True;
        uargs.P = True;
        uargs.o = True;
        uargs.n = True;
        uargs.i = True;
    elif not uargs.U and not uargs.S and not uargs.G and not uargs.r and not uargs.p and not uargs.P and not uargs.o and not uargs.n and not uargs.i and not uargs.e:
        uargs.a = True;
    elif uargs.spray and uargs.brute:
        cprint("[E]: You may only choose to brute force or spray passwords in a single instance", "red",
               attrs=["bold"]);
        exit(1);
    elif uargs.spray:
        uargs.U = True;
    else:
        uargs.a = False;

    # check if null creds wanted
    if uargs.j:
        uargs.u = "Enum4Linux";
        uargs.p = "Py";

    return uargs;


def checkDependentProgs(proglist, verbose):
    if sys.platform.lower() is "windows":
        cprint(
            "[E] Enum4LinuxPy is meant to be ran in an *unix type of environment. The reason for this is due to the fact that Enum4LinuxPy utilizes tools like smbclient and rpcclient, which are usually only found in *unix type environments.",
            "red", attrs=["bold"]);
        exit(1);

    for prog in proglist:
        response = subprocess.run(["which", "{}".format(prog)], stdout=subprocess.PIPE);

        if response.returncode is 0 and verbose:
            cprint("[V]: {} is present on this machine.".format(prog), "green", attrs=["bold"]);
        elif response.returncode is not 0:
            cprint("ERROR: {} is not in your path.".format(prog), "red", attrs=["bold"]);
            exit(1);


def checkOptProgs(proglist, verbose):
    for prog in proglist:
        response = subprocess.run(["which", "{}".format(prog)], stdout=subprocess.PIPE);

        if response.returncode is 0 and verbose:
            cprint("[V]: {} is present on this machine.".format(prog), "green", attrs=["bold"]);
        elif response.returncode is not 0:
            cprint("WARNING: {} is not in your path.".format(prog), "yellow", attrs=["bold"]);


def getArgs():
    parser = argparse.ArgumentParser(description="""
    Simple wrapper around the tools in the samba package to provide similar 
    functionality to enum.exe (formerly from www.bindview.com).  Some additional 
    features such as RID cycling have also been added for convenience.
    """,
                                     usage="""python Enum4LinuxPy.py -t <target> <options>
    E.g:
    python Enum4LinuxPy.py -t 10.10.x.x -a
    python Enum4LinuxPy.py -t 10.20.x.x -l
    python Enum4LinuxPy.py -t 192.168.x.x -R 1000-2000 500-600 -k administrator wsusadmin exchadmin root guest admin

    NOTE that -R or -k take a list as arguments and only require a space separation delimitation)""",
                                     prog="Enum4LinuxPy https://github.com/0v3rride (Ryan Gore)",
                                     epilog="""
    RID cycling should extract a list of users from Windows (or Samba) hosts       
    which have RestrictAnonymous set to 1 (Windows NT and 2000), or "Network    
    access: Allow anonymous SID/Name translation" enabled (XP, 2003).         

    NB: Samba servers often seem to have RIDs in the range 3000-3050.         

    Dependancy info: You will need to have the samba package installed as this  
    script is basically just a wrapper around rpcclient, net, nmblookup and     
    smbclient.  Polenum from http://labs.portcullis.co.uk/application/polenum/
    is required to get Password Policy info.                                  
    """);

    std = parser.add_argument_group("Options similar to Enum4Linux.pl");
    std.add_argument("-t", required=True, type=str, default=None, help="specifiy the remote host");
    std.add_argument("-u", required=False, type=str, default="", help="specifiy username to use (default 'root')");
    std.add_argument("-p", required=False, type=str, default="", help="specifiy password to use (default 'root')");
    std.add_argument("-d", required=False, action="store_true", default=False,
                     help="be detailed, applies to -U and -S");
    std.add_argument("-G", required=False, action="store_true", default=False, help="get group and member list");
    std.add_argument("-P", required=False, action="store_true", default=False, help="get password policy information");
    std.add_argument("-S", required=False, action="store_true", default=False, help="get sharelist");
    std.add_argument("-U", required=False, action="store_true", default=False, help="get userlist");
    std.add_argument("-j", required=False, action="store_true", default=False,
                     help="junk creds (sometimes null session enumeration will not work with null creds)");

    # Crap that wasn't implemented according to comments in enum4linux.pl (will work on this later)
    # std.add_argument("-L", required=False, action="store_true", default=False, help="enum lsa policy);
    # std.add_argument("-N", required=False, action="store_true", default=False, help="enum names);
    # std.add_argument("-M", required=False, action="store_true", default=False, help="get machine list");
    # std.add_argument("-F", required=False, action="store_true", default=False, help=");
    # std.add_argument("-D", required=False, action="store_true", default=False, help=");

    addops = parser.add_argument_group("Additional options");
    addops.add_argument("-r", required=False, action="store_true", default=False,
                        help="enumerate users via RID cycling");
    addops.add_argument("-i", required=False, action="store_true", default=False, help="Get printer information");
    addops.add_argument("-o", required=False, action="store_true", default=False, help="Get OS information");
    addops.add_argument("-n", required=False, action="store_true", default=False,
                        help="Do an nmblookup (similar to nbtstat)");
    addops.add_argument("-l", required=False, action="store_true", default=False,
                        help="Get some (limited) info via LDAP 389/TCP (for DCs only)");
    addops.add_argument("-v", required=False, action="store_true", default=False,
                        help="Verbose. Shows full commands being run (net, rpcclient, etc.)");
    addops.add_argument("-e", required=False, action="store_true", default=False, help="enumerate privileges");
    addops.add_argument("-y", required=False, action="store_true", default=False,
                        help="attempt to enumerate Domain Controller names");
    addops.add_argument("-z", required=False, action="store_true", default=False,
                        help="enumerate running services on remote host using supplied credentials (most likely will need privileged credentials)");
    addops.add_argument("-q", required=False, action="store_true", default=False,
                        help="attempt to enumerate domain information");
    addops.add_argument("--nomemberlist", required=False, action="store_true", default=False,
                        help="Do not list out the group memberships when enumerating groups and member lists");
    addops.add_argument("-a", required=False, action="store_true", default=False, help="""
    Do all simple enumeration (-U -S -G -P -r -o -n -i).
    This option is enabled if you don't provide any other options.""");
    addops.add_argument("-K", required=False, type=int, default=10, help="""
    Keep searching RIDs until n number of consecutive RIDs don't correspond to a username. 
    Implies RID range ends at highest_rid. Useful against DCs (default 10).""");
    addops.add_argument("-k", required=False, type=str, nargs='+',
                        default=["administrator", "guest", "krbtgt", "domain admins", "root", "bin", "none"], help="""
    User(s) that exists on remote system (default: ["administrator", "guest", "krbtgt", "domain admins", "root", "bin", "none"].
    Used to get sid with "lookupsid known_username" Use spaces to try several users: -k admin user1 user2)""")
    addops.add_argument("-w", required=False, type=str, default=None,
                        help="Specify workgroup manually (usually found automatically)");
    addops.add_argument("-s", required=False, type=str, default=None,
                        help="path to list for brute force guessing share names");
    addops.add_argument("-R", required=False, type=str, nargs='+', default=["500-550", "1000-1050"],
                        help="RID ranges to enumerate (default: rid_range, implies -r) Use spaces to try several rid ranges: -R 0-100 1000-2500 500-600)");

    passops = parser.add_argument_group("Password spraying and brute forcing options");
    passops.add_argument("--brute", required=False, type=str, default=None,
                         help="Perform brute forcing using rpcclient (value should be username)");
    passops.add_argument("--wordlist", required=False, type=str, default=None,
                         help="Wordlist to use when brute forcing (value should be absolute path to wordlist)");
    passops.add_argument("--spray", required=False, type=str, default=None,
                         help="Perform password spray using rpcclient (value should be password to spray, a user list is built when enumerating them if possible)");
    passops.add_argument("--timeout", required=False, type=int, default=None,
                         help="The timeout period in between each credential check (timeout is in seconds) (default: None)");
    passops.add_argument("--randtimeout", required=False, type=int, default=None,
                         help="The celling value for random timeout period in between each credential check (timeout is in seconds starting at 0 to <value given> (default: None))");

    return parser.parse_args();


def get_workgroup(args):
    try:
        if args.v:
            cprint("[V] Attempting to get domain name", "yellow", attrs=["bold"]);

        output = str(subprocess.check_output(["nmblookup", "-A", str(args.t)]).decode("UTF-8"));

        for line in output.splitlines():
            if "       <00> - <GROUP>" in line:
                args.w = line.strip().split(' ')[0];
                print("[+]: Obtained domain/workgroup name: {}\n".format(args.w));

    except subprocess.CalledProcessError as cpe:
        cprint("[E] Can't find workgroup/domain\n", "red", attrs=["bold"]);
        args.w = "";


def get_domain_info(args):
    try:
        if args.v:
            cprint("[V] Attempting to get domain information with querydominfo\n", "yellow", attrs=["bold"]);

        output = subprocess.check_output(
            ["rpcclient", "-W", args.w, "-U", "{}%{}".format(args.u, args.p), args.t, "-c", "querydominfo"]).decode(
            "UTF-8");

        if output is not None:
            print(output);
    except subprocess.CalledProcessError as cpe:
        cprint("[E] Unable to get domain information\n", "red", attrs=["bold"]);


def get_dc_names(args):
    try:
        if args.v:
            cprint("[V] Attempting to get domain controller information with dsr_getdcname\n", "yellow",
                   attrs=["bold"]);

        output = subprocess.check_output(["rpcclient", "-W", args.w, "-U", "{}%{}".format(args.u, args.p), args.t, "-c",
                                          "dsr_getdcname {}".format(args.w)]).decode("UTF-8");

        if output is not None:
            print(output);
    except subprocess.CalledProcessError as cpe:
        cprint("[E] Unable to get DC name and information\n", "red", attrs=["bold"]);

    try:
        if args.v:
            cprint("[V] Attempting to get a domain controller name with getdcname\n", "yellow", attrs=["bold"]);

        output = subprocess.check_output(["rpcclient", "-W", args.w, "-U", "{}%{}".format(args.u, args.p), args.t, "-c",
                                          "getdcname {}".format(str(args.w).split('.')[0])]).decode("UTF-8");

        if output is not None:
            cprint("[+] UNC Path Found: {}\n".format(output), "green", attrs=["bold"]);
            listout = subprocess.Popen(
                ["smbclient", "-L", r"{}".format((str(output).strip("\n\r\t\0"))), "-W", args.w, "-U",
                 "{}%{}".format(args.u, args.p)], stdout=subprocess.PIPE).stdout.read().decode("UTF-8");

            if listout is not None:
                cprint(listout, "green", attrs=["bold"]);

    except subprocess.CalledProcessError as cpe:
        if str(cpe.output.decode("UTF-8")).find("WERR_NOT_SUPPORTED") > -1:
            cprint("[E] The rpcclient command 'getdcname' only works against Domain Controllers\n", "red",
                   attrs=["bold"]);
        else:
            cprint("[E] Unable to get DC name and information\n", "red", attrs=["bold"]);


def get_nbtstat(target):
    try:
        output = subprocess.check_output(["nmblookup", "-A", target]).decode("UTF-8");
        mac = output.splitlines()[len(output.splitlines()) - 2];
        print("{}\n{}\n\n{}\n".format(output.splitlines()[0], nbt_to_human(output), mac));
    except subprocess.CalledProcessError as cpe:
        cprint(cpe.output.decode("UTF-8"), "red", attrs=["bold"]);


def nbt_to_human(output):
    stringbuilder = [];
    servicedata = re.findall("(\t[\w\-\.]+|<\w{1,2}>)", output, re.I);
    servicedata.remove("\tMAC");
    counter = 0;

    for line in output.splitlines():
        if counter < len(servicedata):
            servicename = servicedata[counter].strip("\t");

            if re.search("(..__MSBROWSE__.|INet~Services|IS~|IRISMULTICAST|IRISNAMESERVER|Forte_\$ND800ZA)",
                         servicename, re.I):
                stringbuilder.append(
                    "{}\t{}".format(line, nbt_info[servicename, servicedata[counter + 1].strip("<>")]));
                counter = (counter + 2);
            elif re.search("<GROUP>", line, re.I) and re.search("<00>", line, re.I):
                stringbuilder.append("{}\t{}".format(line, nbt_info["", "02"]));
                counter = (counter + 2);
            elif not re.search("(..__MSBROWSE__.|INet~Services|IS~|IRISMULTICAST|IRISNAMESERVER|Forte_\$ND800ZA)",
                               servicename, re.I) and re.search(servicedata[counter + 1], line, re.I):
                stringbuilder.append("{}\t{}".format(line, nbt_info["", servicedata[counter + 1].strip("<>")]));
                counter = (counter + 2);

    return "\n".join(stringbuilder);


def make_session(args):
    try:
        if args.v:
            cprint("[V] Attempting to make null session", "yellow", attrs=["bold"]);
        output = subprocess.check_output(
            ["smbclient", "-W", args.w, r"//{}/ipc$".format(args.t), "-U", "{}%{}".format(args.u, args.p), "-c",
             "help"]).decode("UTF-8");

        if output.find("session setup failed") > -1:
            cprint(
                "[E] Server doesn't allow session using username '{}', password '{}'.  Aborting remainder of tests.\n".format(
                    args.u, args.p), "red", attrs=["bold"]);
            exit(1);
        else:
            cprint("[+] Server {} allows sessions using username '{}', password '{}'\n".format(args.t, args.u, args.p),
                   "green", attrs=["bold"]);
    except subprocess.CalledProcessError as cpe:
        cprint(
            "[E] Server doesn't allow session using username '{}', password '{}'.  Aborting remainder of tests.\n".format(
                args.u, args.p), "red", attrs=["bold"]);
        exit(1);


def get_ldapinfo(args):
    try:
        if args.v:
            cprint("[V] Attempting to get long domain name", "yellow", attrs=["bold"]);

        output = subprocess.check_output(
            ["ldapsearch", "-x", "-h", args.t, "-p", "389", "-s", "base", "namingContexts"]).decode("UTF-8");

        if output.find("ldap_sasl_bind") > -1:
            cprint("[E] Connection error\n", "red", attrs=["bold"]);
        else:
            print(output);

        # PARSE LDAP STRING

    except subprocess.CalledProcessError as cpe:
        cprint(
            "[E] Dependent program ldapsearch not present. Skipping this check. Install ldapsearch to fix this issue\n".format(
                args.u, args.p), "red", attrs=["bold"]);


def get_domain_sid(args):
    try:
        if args.v:
            cprint("[V] Attempting to get domain SID", "yellow", attrs=["bold"]);

        output = subprocess.check_output(
            ["rpcclient", "-W", args.w, "-U", "{}%{}".format(args.u, args.p), args.t, "-c", "'lsaquery'"]).decode(
            "UTF-8");

        if (output.find("Domain Sid: S-0-0") > -1 or output.find("Domain Sid: (NULL SID)") > -1):
            print("[+] Host is part of a workgroup (not a domain)\n");
        elif (re.search("Domain Sid: S-\d+-\d+-\d+-\d+-\d+-\d+", output, re.I)):
            print("[+] Host is part of a domain (not a workgroup)\n");
            print("[+] {}".format(output));

            if (args.w is None or args.w is "" or args.w is " "):
                for line in output.splitlines():
                    if line.find("Domain Name:") > -1:
                        args.w = line.split(": ")[1];
            cprint("[+] Found Domain/Workgroup Name: {}\n".format(args.w), "green", attrs=["bold"]);
        else:
            cprint("[+] Can't determine if host is part of domain or part of a workgroup\n", "yellow", attrs=["bold"]);

    except subprocess.CalledProcessError as cpe:
        cprint(cpe.output.decode("UTF-8"), "red", attrs=["bold"]);


def get_os_info(args):
    try:
        # smbclient
        if args.v:
            cprint(
                "[V] Attempting to get OS info with command: smbclient -W {} //{}/ipc\$ -U {}%{} -c 'q'".format(args.w,
                                                                                                                args.t,
                                                                                                                args.u,
                                                                                                                args.p),
                "yellow", attrs=["bold"]);

        output = subprocess.check_output(
            ["smbclient", "-W", args.w, r"//{}/ipc$".format(args.t), "-U", "{}%{}".format(args.u, args.p), "-c",
             "q"]).decode("UTF-8");

        if re.search("(Domain=[^\n]+)", output, re.I):
            print("[+] OS info for {} from smbclient: {}\n".format(args.t, output));
    except subprocess.CalledProcessError as cpe:
        cprint("SMBCLIENT Error: {}".format(cpe.output.decode("UTF-8")), "red", attrs=["bold"]);

    try:
        # rpcclient
        if args.v:
            cprint("[V] Attempting to get OS info with command: rpcclient -W {} -U {}%{} -c srvinfo {}".format(args.w,
                                                                                                               args.u,
                                                                                                               args.p,
                                                                                                               args.t),
                   "yellow", attrs=["bold"]);

        output = subprocess.check_output(
            ["rpcclient", "-W", args.w, "-U", r"{}%{}".format(args.u, args.p), "-c", "srvinfo", args.t]).decode(
            "UTF-8");

        if (output.find("error: NT_STATUS_ACCESS_DENIED") > -1):
            cprint("[E] Can't get OS info with srvinfo: NT_STATUS_ACCESS_DENIED\n", "red", attrs=["bold"]);
        else:
            print("[+] Got OS info for {} from srvinfo: {}\n".format(args.t, output));
    except subprocess.CalledProcessError as cpe:
        cprint("RPCCLIENT Error: {}".format(cpe.output.decode("UTF-8")), "red", attrs=["bold"]);


def enum_groups(args):
    try:
        groups = ("builtin", "domain");

        for group in groups:

            # GET LIST OF GROUPS
            output = subprocess.check_output(
                ["rpcclient", "-W", args.w, "-U", r"{}%{}".format(args.u, args.p), args.t, "-c",
                 "enumalsgroups {}".format(group)]).decode("UTF-8");

            if (group is "domain"):
                if args.v:
                    cprint("[V] Getting local groups with enumalsgroups\n", "yellow", attrs=["bold"]);

                print("[+] Getting local groups:\n");
            else:
                if args.v:
                    cprint("[V] Getting {} groups with enumalsgroups\n".format(group), "yellow", attrs=["bold"]);

                print("[+] Getting {} groups\n".format(group));

            if (output.find("error: NT_STATUS_ACCESS_DENIED") > -1):
                if (group is "domain"):
                    cprint("[E] Can't get local groups: NT_STATUS_ACCESS_DENIED\n", "red", attrs=["bold"]);
                else:
                    cprint("[E] Can't get {} groups: NT_STATUS_ACCESS_DENIED\n".format(group), "red", attrs=["bold"]);
            else:
                if (re.search("group:", output, re.I)):
                    print(output);

            # GET GROUP NAME, MEMBERS & RID

            if not args.nomemberlist:
                groupdata = re.findall(r"(\[[\w\s\-\_\{\}\.\$]+\])", output, re.I);

                for data in range(0, len(groupdata), 2):
                    print("[+] Information for group '{}' (RID {}):".format(groupdata[data].strip("[]"),
                                                                            int(groupdata[(data + 1)].strip("[]"),
                                                                                16)));

                    doutput = subprocess.Popen(
                        ["net", "rpc", "group", "members", groupdata[data].strip("[]"), "-W", args.w, "-I", args.t,
                         "-U", "{}%{}".format(args.u, args.p)], stdout=subprocess.PIPE).stdout.read().decode("UTF-8");

                    if doutput:
                        print("Member List:\n{}".format(doutput));
                    else:
                        cprint("\tIt appears that this group has no members\n", "yellow", attrs=["bold"]);

                    if args.d:
                        get_group_details_from_rid(int(groupdata[(data + 1)].strip("[]"), 16), args);

                print("\n");
    except subprocess.CalledProcessError as cpe:
        cprint(cpe.output.decode("UTF-8"), "red", attrs=["bold"]);


def get_group_details_from_rid(rid, args):
    try:
        if args.v:
            cprint("[V] Attempting to get detailed group info", "yellow", attrs=["bold"]);

        output = subprocess.check_output(
            ["rpcclient", "-W", args.w, "-U", "{}%{}".format(args.u, args.p), "-c", "querygroup {}".format(str(rid)),
             args.t]).decode("UTF-8");

        if output:
            print("{}\n".format(output));
        else:
            cprint("[E] No info found\n", "red", attrs=["bold"]);
    except subprocess.CalledProcessError as cpe:
        cprint(cpe.output.decode("UTF-8"), "red", attrs=["bold"]);


def enum_password_policy(args):
    try:
        output = subprocess.check_output(["polenum", "{}:{}@{}".format(args.u, args.p, args.t)]).decode("UTF-8");

        if args.v:
            cprint("[V] Attempting to get Password Policy info", "yellow", attrs=["bold"]);

        if (output):
            if (output.find("Account Lockout Threshold") > -1):
                print(output);
            elif (output.find("Error Getting Password Policy: Connect error") > -1):
                cprint("[E] Can't connect to host with supplied credentials.\n", "red", attrs=["bold"]);
            else:
                cprint("[E] Unexpected error from polenum.py:\n", "red", attrs=["bold"]);
                print(output);
        else:
            print("[E] polenum.py gave no output.\n");
    except subprocess.CalledProcessError as cpe:
        print(cpe.output.decode("UTF-8"));
        return 0;


def enum_users(args):
    try:
        if args.v:
            cprint("[V] Attempting to get userlist with querydispinfo", "yellow", attrs=["bold"]);

        output = subprocess.check_output(
            ["rpcclient", "-W", args.w, "-c querydispinfo", "-U", "{}%{}".format(args.u, args.p), args.t]).decode(
            "UTF-8");

        print(output);

        print("\n");

        # GET USER RIDS
        userenumdata = subprocess.check_output(
            ["rpcclient", "-W", args.w, "-c enumdomusers", "-U", "{}%{}".format(args.u, args.p), args.t]).decode(
            "UTF-8");
        userdata = re.findall(r"(\[[\w\s\-\_\{\}\.\$]+\])", userenumdata, re.I);

        if args.v:
            cprint("[V] Attempting to get userlist with enumdomusers", "yellow", attrs=["bold"]);

        if userenumdata.find("NT_STATUS_ACCESS_DENIED") > -1:
            cprint("[E] Couldn't find users using querydispinfo: NT_STATUS_ACCESS_DENIED\n", "red", attrs=["bold"]);
        elif userenumdata.find("NT_STATUS_INVALID_PARAMETER") > -1:
            cprint("[E] Couldn't find users using querydispinfo: NT_STATUS_INVALID_PARAMETER\n", "red", attrs=["bold"]);
        else:
            for data in range(0, len(userdata), 2):
                user_list.append(userdata[data].strip("[]"));
                print("User: {}\{} ----- RID: {}".format(args.w, userdata[data].strip("[]"),
                                                         int(userdata[(data + 1)].strip("[]"), 16)));

            print("");
    except subprocess.CalledProcessError as cpe:
        if cpe.output.decode("UTF").find("NT_STATUS_ACCESS_DENIED") > -1:
            cprint("[E] Couldn't find users using querydispinfo: NT_STATUS_ACCESS_DENIED\n", "red", attrs=["bold"]);
        elif cpe.output.decode("UTF").find("NT_STATUS_INVALID_PARAMETER") > -1:
            cprint("[E] Couldn't find users using querydispinfo: NT_STATUS_INVALID_PARAMETER\n", "red", attrs=["bold"]);


def enum_shares(args):
    output = None;

    try:
        if args.v:
            cprint("[V] Attempting to get share list using authentication", "yellow", attrs=["bold"]);

        # my $shares = `net rpc share -W '$global_workgroup' -I '$global_target' -U'$global_username'\%'$global_password' 2>&1`; #perl example with net rpc command
        output = subprocess.check_output(
            ["smbclient", "-W", args.w, "-L", r"//{}".format(args.t), "-U", "{}%{}".format(args.u, args.p)]).decode(
            "UTF-8");

        if output.find("NT_STATUS_ACCESS_DENIED") > -1:
            cprint("[E] Can't list shares: NT_STATUS_ACCESS_DENIED\n", "red", attrs=["bold"]);
        else:
            print(output);
    except subprocess.CalledProcessError as cpe:
        cprint(cpe.output.decode("UTF-8"), "red", attrs=["bold"]);

    try:
        print("\n[+] Attempting to map shares on {}\n".format(args.t));

        # Filter down the share list returned from the smbclient list command above
        shares = re.findall("\t([\S]+?)\s+(?:Disk|IPC|Printer|-{4,})", output, re.I);

        # Remove any line from the list shares that contains 4 or more -'s in it with a comprehension list (not pretty but it works for now, the number may need to be changed depending on the environment, sharename, etc.)
        sharelist = [s for s in shares if not re.search("-{4,}", s, re.I)];


        for share in sharelist:
            if args.v:
                cprint("[V] Attempting map to share //{}/{} with smbclient\n".format(args.t, share), "yellow",
                       attrs=["bold"]);

            map_response = subprocess.Popen(
                ["smbclient", "-W", args.w, r"//{}/{}".format(args.t, share), "-U", "{}%{}".format(args.u, args.p),
                 "-c dir"], stdout=subprocess.PIPE).stdout.read().decode("UTF-8");

            if map_response.find("NT_STATUS_ACCESS_DENIED listing") > -1:
                cprint("""\t[-] Share: {}
            Mapping: OK
            Listing: DENIED\n
                """.format(share), "red", attrs=["bold"]);
            elif map_response.find("tree connect failed: NT_STATUS_ACCESS_DENIED") > -1:
                cprint("""\t[-] Share: {}
            Mapping: DENIED
            Listing: N/A\n
                """.format(share), "red", attrs=["bold"]);
            elif re.search("\n\s+\.\.\s+D.*\d{4}\n", map_response, re.I) or re.search("blocks of size|blocks available", map_response, re.I):
                cprint("""\t[+] Share: {}
            Mapping: OK
            Listing: OK\n
                """.format(share), "green", attrs=["bold"]);
            else:
                cprint("\t[E] Can't understand response for {}: {}\n".format(share, map_response), "red",
                       attrs=["bold"]);
    except subprocess.CalledProcessError as cpe:
        cprint(cpe.output.decode("UTF-8"), "red", attrs=["bold"]);


def enum_users_rids(args):
    try:
        # Get SID with known usernames
        for known_username in args.k:
            output = subprocess.Popen(["rpcclient", "-W", args.w, "-U", "{}%{}".format(args.u, args.p), args.t,
                                       "-c lookupnames '{}'".format(known_username)],
                                      stdout=subprocess.PIPE).stdout.read().decode("UTF-8");

            if args.v:
                cprint("[V] Attempting to get SID with lookupnames\n", "yellow", attrs=["bold"]);
                cprint("[V] Assuming that user {} exists\n".format(known_username), "yellow", attrs=["bold"]);

            logon = "username {}, password {}".format(args.u, args.p);

            if output.find("NT_STATUS_ACCESS_DENIED") > -1:
                cprint("[E] Couldn't get SID: NT_STATUS_ACCESS_DENIED.  RID cycling not possible.\n", "red",
                       attrs=["bold"]);
                break;
            elif output.find("NT_STATUS_NONE_MAPPED") > -1:
                if args.v:
                    cprint("[V] User {} doesn't exist. User enumeration should be possible, but SID needed...\n".format(
                        known_username), "yellow", attrs=["bold"]);
                continue;
            elif re.search("(S-1-5-[\d]+-[\d-]+)", output, re.I):
                print("[I] Found new SID: {}".format(output));
                continue;
            elif re.search("(S-1-5-21-[\d]+-[\d-]+)", output, re.I):
                print("[I] Found new SID: {}".format(output));
                continue;
            elif re.search("(S-1-5-22-[\d]+-[\d-]+)", output, re.I):
                print("[I] Found new SID: {}".format(output));
                continue;
            else:
                continue;
    except subprocess.CalledProcessError as cpe:
        cprint(cpe.output.decode("UTF-8"), "red", attrs=["bold"]);

    # Get some more SIDs
    try:
        if args.v:
            cprint("[V] Attempting to get SIDs from {} with lsaenumsid\n".format(args.t), "yellow", attrs=["bold"]);

        output = subprocess.Popen(
            ["rpcclient", "-W", args.w, "-U", "{}%{}".format(args.u, args.p), args.t, "-c lsaenumsid"],
            stdout=subprocess.PIPE).stdout.read().decode("UTF-8");

        for sid in output.splitlines():
            if args.v:
                cprint("[V] Processing SID {}\n".format(sid), "yellow", attrs=["bold"]);

            if sid.find("NT_STATUS_ACCESS_DENIED") > -1:
                cprint("[E] Couldn't get SID: NT_STATUS_ACCESS_DENIED.  RID cycling not possible.\n", "red",
                       attrs=["bold"]);
                continue;
            elif re.search("(S-1-5-[\d]+-[\d-]+)", sid, re.I):
                print("[I] Found new SID: {}".format(sid));
                continue;
            elif re.search("(S-1-5-21-[\d]+-[\d-]+)", sid, re.I):
                print("[I] Found new SID: {}".format(sid));
                continue;
            elif re.search("(S-1-5-22-[\d]+-[\d-]+)", sid, re.I):
                print("[I] Found new SID: {}".format(sid));
                continue;
            else:
                continue;

        print("");
    except subprocess.CalledProcessError as cpe:
        cprint(cpe.output.decode("UTF-8"), "red", attrs=["bold"]);


def enum_shares_unauth(args):
    try:
        with open(args.s, "r") as file:
            shares = file.read().splitlines();

        for share in shares:
            output = subprocess.Popen(["smbclient", "-W", args.w, r"//{}/{}".format(args.t, share), "-U", "{}%{}".format(args.u, args.p), "-c", "dir;q"], stdout=subprocess.PIPE).stdout.read().decode("UTF-8");

            if re.search("blocks of size|blocks available", output, re.I):
                cprint("[+] {} EXISTS, allows access using username: {}, password: {}\n".format(share, args.u, args.p), "green", attrs=["bold"]);
            elif re.search("NT_STATUS_ACCESS_DENIED", output, re.I):
                cprint("[+] {} EXISTS, but credentials aren't valid\n".format(share), "yellow", attrs=["bold"]);
            elif re.search("NT_STATUS_BAD_NETWORK_NAME", output, re.I):
                cprint("[-] {} doesn't exist\n".format(share), "red", attrs=["bold"]);
            else:
                cprint("Cannot understand response: {}".format(output), "red", attrs=["bold"]);
    except subprocess.CalledProcessError as cpe:
        cprint(cpe.output.decode("UTF-8"), "red", attrs=["bold"]);
    except FileNotFoundError as fnfe:
        cprint("Path to file containing a list of share names is not valid", "red", attrs=["bold"]);


def enum_privs(args):
    try:
        if args.v:
            cprint("[V] Attempting to get privilege info with enumprivs\n", "yellow", attrs=["bold"]);

        output = subprocess.check_output(
            ["rpcclient", "-W", args.w, "-U", "{}%{}".format(args.u, args.p), "-c enumprivs", args.t]).decode("UTF-8");

        print("{}\n".format(output));

    except subprocess.CalledProcessError as cpe:
        cprint(cpe.output.decode("UTF-8"), "red", attrs=["bold"]);


def get_printer_info(args):
    try:
        if args.v:
            cprint("[V] Attempting to get printer info with enumprinters\n", "yellow", attrs=["bold"]);

        output = subprocess.check_output(
            ["rpcclient", "-W", args.w, "-U", "{}%{}".format(args.u, args.p), "-c enumprinters", args.t]).decode(
            "UTF-8");

        print("{}\n\n".format(output));
    except subprocess.CalledProcessError as cpe:
        cprint(cpe.output.decode("UTF-8"), "red", attrs=["bold"]);


def enum_services(args):
    try:
        if args.v:
            cprint("[V] Attempting to get a list of services with net service list\n", "yellow", attrs=["bold"]);

        output = subprocess.check_output(
            ["net", "rpc", "service", "list", "-I", args.t, "-U", "{}\\{}%{}".format(args.w, args.u, args.p)]).decode(
            "UTF-8");

        print(output);
    except subprocess.CalledProcessError as cpe:
        if str(cpe.output.decode("UTF-8")).find("NT_STATUS_LOGON_FAILURE"):
            cprint("[E] Could not get a list of services, because of invalid credentials\n", "red", attrs=["bold"]);
        else:
            cprint("[E] Could not get a list of services\n", "red", attrs=["bold"]);


def pass_spray(args):
    try:
        if args.v:
            cprint("[V] Attempting to obtain valid credentials via password spray (timeout set to {} seconds)".format(
                args.timeout), "red", attrs=["bold"]);

        count = 0;

        for user in user_list:
            count = count + 1;

            output = subprocess.Popen(
                ["rpcclient", "-W", args.w, "-U", "{}%{}".format(user, args.spray), "-c getusername;quit", args.t],
                stdout=subprocess.PIPE).stdout.read().decode("UTF-8");

            if output.find("Cannot connect to server") > -1 or output.find("Error was NT_STATUS_LOGON_FAILURE") > -1:
                cprint("[{}] Username: '{}'\tPassword: '{}'\tResult: invalid".format(count, user, args.spray), "red",
                       attrs=["bold"]);
            elif output.find("Account Name") > -1 or output.find("Authority Name") > -1:
                cprint("[{}] Username: '{}'\tPassword: '{}'\tResult: !*****VALID*****!".format(count, user, args.spray),
                       "green", attrs=["bold"]);
            else:
                print(output);

            if args.timeout and args.randtimeout is None:
                if args.v:
                    cprint("[V] Timeout for {} seconds".format(str(args.timeout)), "yellow", attrs=["bold"]);

                time.sleep(float(args.timeout));
            elif args.timeout is None and args.randtimeout:
                tout = random.randint(0, args.randtimeout);

                if args.v:
                    cprint("[V] Timeout for {} seconds".format(str(tout)), "yellow", attrs=["bold"]);

                time.sleep(float(tout));

        print("");
    except subprocess.CalledProcessError as cpe:
        cprint(cpe.output.decode("UTF-8"), "red", attrs=["bold"]);


def brute_pass(args):
    try:
        words = open(args.wordlist, "r").read().splitlines();

        count = 0;

        for word in words:
            count = count + 1;
            
            output = subprocess.Popen(
                ["rpcclient", "-W", args.w, "-U", "{}%{}".format(args.brute, word), args.t, "-c getusername;quit"],
                stdout=subprocess.PIPE).stdout.read().decode("UTF-8");

            if output.find("Cannot connect to server") > -1 or output.find("Error was NT_STATUS_LOGON_FAILURE") > -1:
                cprint("[{}] Username: '{}'\tPassword: '{}'\tResult: invalid".format(count, args.brute, word), "red",
                       attrs=["bold"]);
            elif output.find("Account Name") > -1 or output.find("Authority Name") > -1:
                cprint("[{}] Username: '{}'\tPassword: '{}'\tResult: !*****VALID*****!".format(count, args.brute, word),
                       "green", attrs=["bold"]);
            else:
                print(output);

            if args.timeout and args.randtimeout is None:
                if args.v:
                    cprint("[V] Timeout for {} seconds".format(str(args.timeout)), "yellow", attrs=["bold"]);

                time.sleep(float(args.timeout));
            elif args.timeout is None and args.randtimeout:
                tout = random.randint(0, args.randtimeout);

                if args.v:
                    cprint("[V] Timeout for {} seconds".format(str(tout)), "yellow", attrs=["bold"]);

                time.sleep(float(tout));

        print("");
    except subprocess.CalledProcessError as cpe:
        cprint(cpe.output.decode("UTF-8"), "red", attrs=["bold"]);
    except FileNotFoundError as fnfe:
        cprint("[E] File path specified is not valid", "red", attrs=["bold"]);


def main():
    timestart = datetime.datetime.now();

    carglist = setArgs(getArgs());
    checkDependentProgs(dependent_programs, carglist.v);
    checkOptProgs(optional_dependent_programs, carglist.v);

    if carglist.v:
        print("""
         _____                        ___  _     _                 ______      
        |  ___|                      /   || |   (_)                | ___ \     
        | |__ _ __  _   _ _ __ ___  / /| || |    _ _ __  _   ___  _| |_/ /   _ 
        |  __| '_ \| | | | '_ ` _ \/ /_| || |   | | '_ \| | | \ \/ /  __/ | | |
        | |__| | | | |_| | | | | | \___  || |___| | | | | |_| |>  <| |  | |_| |
        \____/_| |_|\__,_|_| |_| |_|   |_/\_____/_|_| |_|\__,_/_/\_\_|   \__, |
                                                                          __/ |
                                                                         |___/
        """);

    print("""
[*] https://github.com/0v3rride
[*] Script has started...
[*] Use CTRL+C to cancel the script at anytime.

!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
CREDIT FOR THE ORIGINAL PERL VERSION OF ENUM4LINUX GOES 
TO MARK LOWE, PORTCULLIS LABS & CONTRIBUTORS TO THE 
ENUM4LINUX PROJECT
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!


+------------------------------+
|     TARGETING INFORMATION    |
+------------------------------+
Starting Enum4LinuxPy at {}
Target --------------------> {}
RID Ranges ----------------> {}
Username ------------------> {}
Password ------------------> {}
Known Usernames -----------> {}
""".format(timestart.strftime("%b %d %Y %H:%M:%S"), carglist.t, carglist.R, carglist.u, carglist.p, carglist.k));

    # Basic Enumeration & Check Session----------------------------------------------------------------------------

    # WORKGOUP/DOMAIN NAME INFORMATION
    title = [["Enumerating Workgroup/Domain on {}".format(carglist.t).title()]];
    header = terminaltables.AsciiTable(title);
    print(header.table);

    if not carglist.w:
        get_workgroup(carglist);
    else:
        cprint("[+]: Domain/workgroup name specified: {}\n".format(carglist.w), "green", attrs=["bold"]);

    # NMBLOOKUP/NBTSCAN
    if (carglist.n):
        title = [["NBTStat Information for {}".format(carglist.t).title()]];
        header = terminaltables.AsciiTable(title);
        print(header.table);
        get_nbtstat(carglist.t);

    # NULL SESSION CHECK
    title = [["Session Check on {}".format(carglist.t).title()]];
    header = terminaltables.AsciiTable(title);
    print(header.table);

    make_session(carglist);

    # GET LDAP INFO
    if (carglist.l):
        title = [["Getting information via LDAP for {}".format(carglist.t).title()]];
        header = terminaltables.AsciiTable(title);
        print(header.table);

        get_ldapinfo(carglist);

    # GET DOMAIN SID
    title = [["Getting domain SID for {}".format(carglist.t).title()]];
    header = terminaltables.AsciiTable(title);
    print(header.table);

    get_domain_sid(carglist);

    # GET OS Information
    if (carglist.o):
        title = [["Getting OS information for {}".format(carglist.t).title()]];
        header = terminaltables.AsciiTable(title);
        print(header.table);

        get_os_info(carglist);

    # Query-compatible functions-----------------------------------------------------------------------------------
    if (carglist.q):
        title = [["Getting Domain Information {}".format(carglist.t).title()]];
        header = terminaltables.AsciiTable(title);
        print(header.table);

        get_domain_info(carglist);

    if (carglist.y):
        title = [["Getting Domain Controller Information {}".format(carglist.t).title()]];
        header = terminaltables.AsciiTable(title);
        print(header.table);

        get_dc_names(carglist);

    # Enum-compatiable functions-----------------------------------------------------------------------------------

    if (carglist.U):
        title = [["Users on {}".format(carglist.t).title()]];
        header = terminaltables.AsciiTable(title);
        print(header.table);

        enum_users(carglist);

    if (carglist.S):
        title = [["Share Enumeration on {}".format(carglist.t).title()]];
        header = terminaltables.AsciiTable(title);
        print(header.table);

        enum_shares(carglist);

    if (carglist.P):
        title = [["Password Policy Information for {}".format(carglist.t).title()]];
        header = terminaltables.AsciiTable(title);
        print(header.table);

        enum_password_policy(carglist);

    if (carglist.G):
        title = [["Groups on {}".format(carglist.t).title()]];
        header = terminaltables.AsciiTable(title);
        print(header.table);

        enum_groups(carglist);
        # enum_dom_groups(carglist);

        # enum_machines()
        # enum_lsa_policy()

    # Enumerate privileges
    if (carglist.e):
        title = [["Privileges Enumeration on {}".format(carglist.t).title()]];
        header = terminaltables.AsciiTable(title);
        print(header.table);

        enum_privs(carglist);

    if carglist.z:
        title = [["Service enumeration on {}".format(carglist.t).title()]];
        header = terminaltables.AsciiTable(title);
        print(header.table);

        enum_services(carglist);

    # Misc functions-----------------------------------------------------------------------------------------------
    if carglist.r:
        title = [["Users on {} via RID cycling (RIDS: {})".format(carglist.t, carglist.R).title()]];
        header = terminaltables.AsciiTable(title);
        print(header.table);

        enum_users_rids(carglist);

    if carglist.s:
        title = [["Brute Force Share Enumeration on {}".format(carglist.t).title()]];
        header = terminaltables.AsciiTable(title);
        print(header.table);

        enum_shares_unauth(carglist);

    if carglist.i:
        title = [["Getting printer info for {}".format(carglist.t).title()]];
        header = terminaltables.AsciiTable(title);
        print(header.table);

        get_printer_info(carglist);

    # Extended functions-------------------------------------------------------------------------------------------
    if carglist.spray:
        if len(user_list) > 0:
            title = [["Starting password spray against {}".format(carglist.t).title()]];
            header = terminaltables.AsciiTable(title);
            print(header.table);

            pass_spray(carglist);
        elif len(user_list) <= 0:
            cprint(
                "[E]: The user list is not populated, which means no users were able to be found. Aborting password spraying procedures.\n",
                "red", attrs=["bold"]);
        else:
            cprint("[E]: Unable to perform password spraying procedures\n", "red", attrs=["bold"]);

    if carglist.brute:
        if carglist.wordlist:
            title = [["Starting brute force on {} against user {}".format(carglist.t, carglist.brute).title()]];
            header = terminaltables.AsciiTable(title);
            print(header.table);

            brute_pass(carglist);
        elif not carglist.wordlist:
            cprint("[E]: The absolute path to a wordlist is required\n", "red", attrs=["bold"]);
        else:
            cprint("[E]: Unable to perform brute forcing procedures\n", "red", attrs=["bold"]);

    # Enum4LinuxPy complete----------------------------------------------------------------------------------------
    timeend = datetime.datetime.now();
    elapsedtime = (timeend - timestart);
    cprint("[!] Enum4LinuxPy completed at {} - Duration of time ran for {}\n".format(timeend, elapsedtime), "magenta",
           attrs=["bold"]);


if __name__ == '__main__':
    try:
        main();
    except KeyboardInterrupt as kbi:
        print("\n!-------Enum4LinuxPy has been stopped-------!\n\n");
