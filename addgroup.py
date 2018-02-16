#!/usr/bin/env python
import argparse
import datetime
import sys
from getpass import getpass

import bitbucket

try:
    from urllib.error import HTTPError, URLError
except ImportError:
    from urllib2 import HTTPError, URLError


_verbose = False
_quiet = False


def debug(message, output_no_verbose=False):
    """
    Outputs a message to stdout taking into account the options verbose/quiet.
    """
    global _quiet, _verbose
    if not _quiet and (output_no_verbose or _verbose):
        print("{0} - {1}".format(datetime.datetime.now(), message))


def exit(message, code=1):
    """
    Forces script termination using C based error codes.
    By default, it uses error 1 (EPERM - Operation not permitted)
    """
    global _quiet
    if not _quiet and message and len(message) > 0:
        sys.stderr.write("%s (%s)\n" % (message, code))
    sys.exit(code)


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Usage: %prog [options] ")
    parser.add_argument("-u", "--username", dest="username", help="Bitbucket username")
    parser.add_argument("-p", "--password", dest="password", help="Bitbucket password")
    parser.add_argument("-t", "--team", dest="team", help="Bitbucket team")
    parser.add_argument("-v", "--verbose", action='store_true', dest="verbose", help="Verbose output of all cloning commands")
    parser.add_argument("-q", "--quiet", action='store_true', dest="quiet", help="No output to stdout")
    parser.add_argument('--skip-password', dest="skip_password", action='store_true', help="Ignores password prompting if no password is provided (for public repositories)")
    args = parser.parse_args()
    username = args.username
    password = args.password
    owner = args.team if args.team else username
    _quiet = args.quiet
    _verbose = args.verbose
    if _quiet:
        _verbose = False  # override in case both are selected
    if not password:
        if not args.skip_password:
            password = getpass(prompt='Enter your bitbucket password: ')
    if not username:
        parser.error('Please supply a username (-u <username>)')

    # ok to proceed
    try:
        bb = bitbucket.BitBucket(username, password, _verbose)
        user = bb.user(owner)
        repos = sorted(user.repositories(), key=lambda repo: repo.get("name"))
        if not repos:
            print("No repositories found. Are you sure you provided the correct password")
        for repo in repos:

            debug("Adding group to [%s]..." % repo.get("name"), True)
            really_the_repo = bb.repository(owner, repo.get("slug"))
            really_the_repo.add_group('fresh-read-only', 'read')

        debug("Finished!", True)
    except HTTPError as err:
        if err.code == 401:
            exit("Unauthorized! Check your credentials and try again.", 22)  # EINVAL - Invalid argument
        else:
            exit("Connection Error! Bitbucket returned HTTP error [%s]." % err.code)
    except URLError as e:
        exit("Unable to reach Bitbucket: %s." % e.reason, 101)  # ENETUNREACH - Network is unreachable
    except (KeyboardInterrupt, SystemExit):
        exit("Operation cancelled.", 0)
    except:
        if not _quiet:
            import traceback
            traceback.print_exc()
        exit("Unknown error.", 11)  # EAGAIN - Try again
