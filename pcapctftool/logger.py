# coding: utf-8
from pcapctftool.session import Session


class Color(object):
    BRIGHT_BLUE = "\u001b[34;1m"
    WHITE = "\u001b[37m"
    CYAN = "\u001b[36m"
    RED = "\u001b[31m"
    GREEN = "\u001b[32m"
    RESET = "\u001b[0m"
    BACKGROUND_RED = "\u001b[41m"


DEBUG_MODE = False
OUTPUT_FILE = None


def _log(content):
    print(content)

    if OUTPUT_FILE:
        OUTPUT_FILE.write(content + "\n")


def debug(*args):
    """
    This should be used to display irmation to the developers, not the users.
    """

    if not DEBUG_MODE:
        return

    if len(args) == 2:
        session = args[0]
        msg = args[1]
        _log("{}[{} {}] {}{}[**]{} {}".format(Color.BRIGHT_BLUE, session.protocol, str(session), Color.RESET, Color.CYAN, Color.RESET, msg))
    else:
        msg = args[0]
        _log("{}[**]{} {}".format(Color.CYAN, Color.RESET, msg))


def info(*args):
    """
    This should be used to display - not necessarily - useful irmation to the users.
    """

    if len(args) == 2:
        session = args[0]
        msg = args[1]
        _log("{}[{} {}] {}{}[i]{}  {}".format(Color.BRIGHT_BLUE, session.protocol, str(session), Color.RESET, Color.GREEN, Color.RESET, msg))
    else:
        msg = args[0]
        _log("{}[i]{} {}".format(Color.GREEN, Color.RESET, msg))


def error(msg: str):
    """
    This should be used when anything goes wrong (not necessarily fatal).
    """
    _log("{}[!]{} {}".format(Color.RED, Color.RESET, msg))


def found(*args):
    """
    This should be used when something valuable has been +.
    """
    if len(args) == 2:
        session = args[0]
        msg = args[1]
        _log("{}[{} {}] {}{}{}[+]{} {}".format(Color.BRIGHT_BLUE, session.protocol, str(session), Color.RESET, Color.WHITE, Color.BACKGROUND_RED, Color.RESET, msg))
    else:
        msg = args[0]
        _log("{}[+]{} {}".format((Color.BRIGHT_BLUE, Color.RESET, msg))