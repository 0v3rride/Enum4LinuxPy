#!/usr/bin/env python3

import argparse;
import subprocess;
import datetime;
import terminaltables;
import re;

#Global Vars
version = "1.0.0";
# target = None;
# fail_limit = 1000;
# search_until_fail = False;
# highest_rid = 999999;
# workgroup = None;
# username = "";
# password = "";
# filename = None;
# share_file = None;
# detailed = False;
# passpol = False;
# verbose = False;
# rid_range = ["500-550", "1000-1050"];
# known_usernames = ["administrator", "guest", "krbtgt", "domain admins", "root", "bin", "none"];
dependent_programs = ["nmblookup", "net", "rpcclient", "smbclient"];
optional_dependent_programs = ["polenum", "ldapsearch"];
# debug = False;
# filename = None;



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

nbt_info = (
["__MSBROWSE__", "01", 0, "Master Browser"],
["INet~Services", "1C", 0, "IIS"],
["IS~", "00", 1, "IIS"],
["", "00", 1, "Workstation Service"],
["", "01", 1, "Messenger Service"],
["", "03", 1, "Messenger Service"],
["", "06", 1, "RAS Server Service"],
["", "1F", 1, "NetDDE Service"],
["", "20", 1, "File Server Service"],
["", "21", 1, "RAS Client Service"],
["", "22", 1, "Microsoft Exchange Interchange(MSMail Connector)"],
["", "23", 1, "Microsoft Exchange Store"],
["", "24", 1, "Microsoft Exchange Directory"],
["", "30", 1, "Modem Sharing Server Service"],
["", "31", 1, "Modem Sharing Client Service"],
["", "43", 1, "SMS Clients Remote Control"],
["", "44", 1, "SMS Administrators Remote Control Tool"],
["", "45", 1, "SMS Clients Remote Chat"],
["", "46", 1, "SMS Clients Remote Transfer"],
["", "4C", 1, "DEC Pathworks TCPIP service on Windows NT"],
["", "52", 1, "DEC Pathworks TCPIP service on Windows NT"],
["", "87", 1, "Microsoft Exchange MTA"],
["", "6A", 1, "Microsoft Exchange IMC"],
["", "BE", 1, "Network Monitor Agent"],
["", "BF", 1, "Network Monitor Application"],
["", "03", 1, "Messenger Service"],
["", "00", 0, "Domain/Workgroup Name"],
["", "1B", 1, "Domain Master Browser"],
["", "1C", 0, "Domain Controllers"],
["", "1D", 1, "Master Browser"],
["", "1E", 0, "Browser Service Elections"],
["", "2B", 1, "Lotus Notes Server Service"],
["IRISMULTICAST", "2F", 0, "Lotus Notes"],
["IRISNAMESERVER", "33", 0, "Lotus Notes"],
['Forte_$ND800ZA', "20", 1, "DCA IrmaLan Gateway Server Service"]
);
####################### end of nbtscan-derrived code ############################


def setArgs(uargs):
    if uargs.a:
        uargs.U = True;
        uargs.S = True;
        uargs.G = True;
        uargs.r = True;
        uargs.P = True;
        uargs.o = True;
        uargs.n = True;
        uargs.i = True;

    # global username
    # global password
    # global detailed
    # global passpol
    # global fail_limit
    # global rid_range
    # global share_file
    # global known_usernames
    # global workgroup
    # global verbose
    # global target

    # username = uargs.u;
    # password = uargs.p;
    # detailed = uargs.d;
    # passpol = uargs.P;
    # fail_limit = uargs.K;
    # rid_range = uargs.R;
    # share_file = uargs.s;
    # known_usernames = uargs.k;
    # workgroup = uargs.w;
    # verbose = uargs.v;
    # target = uargs.t;


    #target
    #uargs.t = r"\\{}".format(uargs.t);

    #check all argument
    if not uargs.U and not uargs.S and not uargs.G and not uargs.r and not uargs.p and not uargs.P and not uargs.o and not uargs.n and not uargs.i:
        uargs.a = True;
    else:
        uargs.a = False;

    return uargs;


def checkDependentProgs(proglist, verbose):
    for prog in proglist:
        response = subprocess.run(["which", "{}".format(prog)], stdout=subprocess.PIPE);

        if response.returncode is 0 and verbose:
            print("[V]: {} is present on this machine.".format(prog));
        elif response.returncode is not 0:
            print("ERROR: {} is not in your path.".format(prog));
            exit(1);


def checkOptProgs(proglist, verbose):
    for prog in proglist:
        response = subprocess.run(["which", "{}".format(prog)], stdout=subprocess.PIPE);

        if response.returncode is 0 and verbose:
            print("[V]: {} is present on this machine.".format(prog));
        elif response.returncode is not 0:
            print("WARNING: {} is not in your path.".format(prog));


def getArgs():
    parser = argparse.ArgumentParser(description = """
    Simple wrapper around the tools in the samba package to provide similar 
    functionality to enum.exe (formerly from www.bindview.com).  Some additional 
    features such as RID cycling have also been added for convenience.
    """, prog="Enum4LinuxPy v{} https://github.com/0v3rride Copyright (C) Ryan Gore".format(version));

    std = parser.add_argument_group("Options similar to Enum4Linux.pl");

    std.add_argument("-t", required=True, type=str, default=None, help="specifiy the remote host");
    std.add_argument("-u", required=False, type=str, default="", help="specifiy username to use (default "")");
    std.add_argument("-p", required=False, type=str, default="", help="specifiy password to use (default "")");
    std.add_argument("-d", required=False, action="store_true", default=False, help="be detailed, applies to -U and -S");
    std.add_argument("-G", required=False, action="store_true", default=False, help="get group and member list");
    std.add_argument("-P", required=False, action="store_true", default=False, help="get password policy information");
    std.add_argument("-S", required=False, action="store_true", default=False, help="get sharelist");
    std.add_argument("-M", required=False, action="store_true", default=False, help="get machine list");
    std.add_argument("-U", required=False, action="store_true", default=False, help="get userlist");

    # parser.add_argument("-L", required=False, action="store_true", default=False, help="get group and member list");
    # parser.add_argument("-N", required=False, action="store_true", default=False, help="get sharelist");
    # parser.add_argument("-D", required=False, action="store_true", default=False, help="get machine list");
    # parser.add_argument("-F", required=False, action="store_true", default=False, help="get group and member list");

    addops = parser.add_argument_group("Additional options");
    addops.add_argument("-r", required=False, action="store_true", default=False, help="enumerate users via RID cycling");
    addops.add_argument("-i", required=False, action="store_true", default=False, help="Get printer information");
    addops.add_argument("-o", required=False, action="store_true", default=False, help="Get OS information");
    addops.add_argument("-n", required=False, action="store_true", default=False, help="Do an nmblookup (similar to nbtstat)");
    addops.add_argument("-l", required=False, action="store_true", default=False, help="Get some (limited) info via LDAP 389/TCP (for DCs only)");
    addops.add_argument("-v", required=False, action="store_true", default=False, help="Verbose. Shows full commands being run (net, rpcclient, etc.)");
    addops.add_argument("-a", required=False, action="store_true", default=False, help="""
    Do all simple enumeration (-U -S -G -P -r -o -n -i).
    This option is enabled if you don't provide any other options.""");
    addops.add_argument("-K", required=False, type=int, default=10, help="""
    Keep searching RIDs until n number of consecutive RIDs don't correspond to a username. 
    Implies RID range ends at highest_rid. Useful against DCs (default 10).""");
    addops.add_argument("-k", required=False, type=str, nargs='+', default=["administrator", "guest", "krbtgt", "domain admins", "root", "bin", "none"], help="""
    User(s) that exists on remote system (default: known_usernames).
    Used to get sid with "lookupsid known_username" Use commas to try several users: -k admin,user1,user2)""")
    addops.add_argument("-w", required=False, type=str, default=None, help="Specify workgroup manually (usually found automatically)");
    addops.add_argument("-s", required=False, type=str, default=None, help="path to list for brute force guessing share names");
    addops.add_argument("-R", required=False, type=str, nargs='+', default=["500-550", "1000-1050"], help="RID ranges to enumerate (default: rid_range, implies -r)");

    return parser.parse_args();


def get_workgroup(args):
    try:
        if args.v:
            print("[V] Attempting to get domain name");

        output = str(subprocess.check_output(["nmblookup", "-A", str(args.t)]).decode("UTF-8"));

        for line in output.splitlines():
            if "       <00> - <GROUP>" in line:
                args.w = line.strip().split(' ')[0];
                print("[+]: Obtained domain/workgroup name: {}\n".format(args.w));

    except subprocess.CalledProcessError as cpe:
        print("[E] Can't find workgroup/domain\n");
        args.w = "";


def get_nbtstat(target):
    try:
        output = subprocess.check_output(["nmblookup", "-A", target]).decode("UTF-8");
        print("{}\n".format(output));
    except subprocess.CalledProcessError as cpe:
        print(cpe.output.decode("UTF-8"));


def make_session(args):
    try:
        if args.v:
            print("[V] Attempting to make null session");
        output = subprocess.check_output(["smbclient", "-W", args.w, r"//{}/ipc$".format(args.t), "-U", "{}%{}".format(args.u, args.p), "-c", "help"]).decode("UTF-8");

        if output.find("session setup failed") > -1:
            print("[E] Server doesn't allow session using username '{}', password '{}'.  Aborting remainder of tests.\n".format(args.u, args.p));
            exit(1);
        else:
            print("[+] Server {} allows sessions using username '{}', password '{}'\n".format(args.t, args.u, args.p));
    except subprocess.CalledProcessError as cpe:
        print("[E] Server doesn't allow session using username '{}', password '{}'.  Aborting remainder of tests.\n".format(args.u, args.p));
        exit(1);


def get_ldapinfo(args):
    try:
        if args.v:
            print("[V] Attempting to get long domain name");

        output = subprocess.check_output(["ldapsearch", "-x", "-h", args.t, "-p", "389", "-s", "base", "namingContexts"]).decode("UTF-8");

        if output.find("ldap_sasl_bind") > -1:
            print("[E] Connection error\n");

        #PARSE LDAP STRING

    except subprocess.CalledProcessError as cpe:
        print("[E] Dependent program ldapsearch not present. Skipping this check. Install ldapsearch to fix this issue\n".format(args.u, args.p));


def get_domain_sid(args):
    try:
        if args.v:
            print("[V] Attempting to get domain SID");

        output = subprocess.check_output(["rpcclient", "-W", args.w, "-U", "{}%{}".format(args.u, args.p), args.t, "-c", "'lsaquery'"]).decode("UTF-8");

        if(output.find("Domain Sid: S-0-0") > -1 or output.find("Domain Sid: (NULL SID)") > -1):
            print("[+] Host is part of a workgroup (not a domain)\n");
        elif(re.search("Domain Sid: S-\d+-\d+-\d+-\d+-\d+-\d+", output, re.I)):
            print("[+] Host is part of a domain (not a workgroup)\n");
            print("[+] {}".format(output));

            if(args.w is None or args.w is "" or args.w is " "):
                for line in output.splitlines():
                    if line.find("Domain Name:") > -1:
                        args.w = line.split(": ")[1];
            print("[+] Found Domain/Workgroup Name: {}\n".format(args.w));
        else:
            print("[+] Can't determine if host is part of domain or part of a workgroup\n");

    except subprocess.CalledProcessError as cpe:
        print(cpe.output.decode("UTF-8"));


def get_os_info(args):
    try:
        #smbclient
        if args.v:
            print("[V] Attempting to get OS info with command: smbclient -W {} //{}/ipc\$ -U {}%{} -c 'q'".format(args.w, args.t, args.u, args.p));

        output = subprocess.check_output(["smbclient", "-W", args.w, r"//{}/ipc$".format(args.t), "-U", "{}%{}".format(args.u, args.p), "-c", "q"]).decode("UTF-8");

        if(output is not None or output is not " " or output is not ""):
            print("[+] OS info for {} from smbclient: {}\n".format(args.t, output));
    except subprocess.CalledProcessError as cpe:
        print("SMBCLIENT Error: {}".format(cpe.output.decode("UTF-8")));

    try:
        #rpcclient
        if args.v:
            print("[V] Attempting to get OS info with command: rpcclient -W {} -U {}%{} -c srvinfo {}".format(args.w, args.u, args.p, args.t));

        output = subprocess.check_output(["rpcclient", "-W", args.w, "-U", r"{}%{}".format(args.u, args.p), "-c", "srvinfo", args.t]).decode("UTF-8");

        if(output.find("error: NT_STATUS_ACCESS_DENIED") > -1):
            print("[E] Can't get OS info with srvinfo: NT_STATUS_ACCESS_DENIED\n");
        else:
            print("[+] Got OS info for {} from srvinfo: {}\n".format(args.t, output));
    except subprocess.CalledProcessError as cpe:
        print("RPCCLIENT Error: {}".format(cpe.output.decode("UTF-8")));


def enum_groups(args):
    try:
        groups = ("builtin", "domain");

        for group in groups:

            #GET LIST OF GROUPS
            output = subprocess.check_output(["rpcclient", "-W", args.w, "-U", r"{}%{}".format(args.u, args.p), args.t, "-c", "enumalsgroups {}".format(group)]).decode("UTF-8");

            if(group is "domain"):
                print("[+] Getting local groups:\n");
            else:
                print("[+] Getting {} groups\n".format(group));

            if (output.find("error: NT_STATUS_ACCESS_DENIED") > -1):
                if(group is "domain"):
                    print("[E] Can't get local groups: NT_STATUS_ACCESS_DENIED\n");
                else:
                    print("[E] Can't get {} groups: NT_STATUS_ACCESS_DENIED\n".format(group));
            else:
                if(re.search("group:.\s", output, re.I), output, re.I):
                    print(output);

                #GET GROUP NAME, MEMBERS & RID

                groupdata = re.findall(r"(\[[\w\s-]+\])", output, re.I);

                for data in range(0, len(groupdata), 2):
                    print("[+] Information for group '{}' (RID {}):".format(groupdata[data].strip("[]"), int(groupdata[(data+1)].strip("[]"), 16)));

                    doutput = subprocess.check_output(["net", "rpc", "group", "members", groupdata[data].strip("[]"), "-I", args.t, "-U", "{}%{}".format(args.u, args.p)]).decode("UTF-8");

                    if doutput or doutput is not " " or doutput is not "":
                        print("Members List:\n{}".format(doutput));
                    else:
                        print("It appears that this group has no members");

                    if args.d:
                        get_group_details_from_rid(int(groupdata[(data+1)].strip("[]"), 16), args);

                print("\n");

    except subprocess.CalledProcessError as cpe:
        print(cpe.output.decode("UTF-8"));


def get_group_details_from_rid(rid, args):
    try:
        if args.v:
            print("[V] Attempting to get detailed group info");

        output = subprocess.check_output(["rpcclient", "-W", args.w, "-U", "{}%{}".format(args.u, args.p), "-c", "querygroup {}".format(str(rid)), args.t]).decode("UTF-8");

        if output:
            print("{}\n".format(output));
        else:
            print("[E] No info found\n");
    except subprocess.CalledProcessError as cpe:
        print(cpe.output.decode("UTF-8"));


def enum_password_policy(args):
    try:
        output = subprocess.check_output(["polenum", "{}:{}@{}".format(args.u, args.p, args.t)]).decode("UTF-8");

        if args.v:
            print("Attempting to get Password Policy info");

        if(output):
            if(output.find("Account Lockout Threshold") > -1):
                print(output);
            elif(output.find("Error Getting Password Policy: Connect error") > -1):
                print("[E] Can't connect to host with supplied credentials.\n");
            else:
                print("[E] Unexpected error from polenum.py:\n");
                print(output);
        else:
            print("[E] polenum.py gave no output.\n");
    except subprocess.CalledProcessError as cpe:
        print(cpe.output.decode("UTF-8"));
        return 0;


def enum_shares(args):
    try:
        if args.v:
            print("[V] Attempting to get share list using authentication");

        # my $shares = `net rpc share -W '$global_workgroup' -I '$global_target' -U'$global_username'\%'$global_password' 2>&1`; #perl example with net rpc command
        output = subprocess.check_output(["smbclient", "-W", args.w, "-L", r"//{}".format(args.t), "-U", "{}%{}".format(args.u, args.p)]).decode("UTF-8");

        if output.find("NT_STATUS_ACCESS_DENIED") > -1:
            print("[E] Can't list shares: NT_STATUS_ACCESS_DENIED\n");
        else:
            print(output);
    except subprocess.CalledProcessError as cpe:
        print(cpe.output.decode("UTF-8"));


def main():
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

+------------------------------+
|     TARGETING INFORMATION    |
+------------------------------+

Starting Enum4LinuxPy v{} at {}
Target --------------------> {}
RID Ranges ----------------> {}
Username ------------------> {}
Password ------------------> {}
Known Usernames -----------> {}
""".format(version, datetime.datetime.now().strftime("%b %d %Y %H:%M:%S"), carglist.t, carglist.R, carglist.u, carglist.p, carglist.k));


    #Basic Enumeration & Check Session--------------------------------------------------------------------

    #WORKGOUP/DOMAIN NAME INFORMATION
    title = [["Enumerating Workgroup/Domain on {}".format(carglist.t).title()]];
    header = terminaltables.AsciiTable(title);
    print(header.table);

    if not carglist.w:
        get_workgroup(carglist);
    else:
        print("[+]: Domain/workgroup name specified: {}\n".format(carglist.w));


    #NMBLOOKUP/NBTSCAN
    if(carglist.n):
        title = [["NBTStat Information for {}".format(carglist.t).title()]];
        header = terminaltables.AsciiTable(title);
        print(header.table);
        get_nbtstat(carglist.t);


    #NULL SESSION CHECK
    title = [["Session Check on {}".format(carglist.t).title()]];
    header = terminaltables.AsciiTable(title);
    print(header.table);

    make_session(carglist);

    #GET LDAP INFO
    if(carglist.l):
        title = [["Getting information via LDAP for {}".format(carglist.t).title()]];
        header = terminaltables.AsciiTable(title);
        print(header.table);

        get_ldapinfo(carglist);

    #GET DOMAIN SID
    title = [["Getting domain SID for {}".format(carglist.t).title()]];
    header = terminaltables.AsciiTable(title);
    print(header.table);

    get_domain_sid(carglist);


    #GET OS Information
    if(carglist.o):
        title = [["Getting OS information for {}".format(carglist.t).title()]];
        header = terminaltables.AsciiTable(title);
        print(header.table);

        get_os_info(carglist);



    #Enum-compatiable functions-------------------------------------------------------------------------------

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


    #enum_names()
    #enum_dom_users()
    #enum_machines()
    #enum_lsa_policy()



if __name__ == '__main__':
    main();
