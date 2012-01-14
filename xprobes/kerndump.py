#!/usr/bin/python

import sys

def seive (ifile, symbol):
    for line in ifile:
        if line.find (symbol) > -1:
            print line


if __name__ == '__main__':
    try:
        systemmap = sys.argv[1]
    except:
        print 'Usage: ' + sys.argv[0] + '<path to your systammap file ..>'
        sys.exit (1)

    seive (open (systemmap, 'r'), 'sys_')

    sys.exit (0)
