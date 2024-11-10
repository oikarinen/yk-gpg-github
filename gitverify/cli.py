# Copyright (c) 2024 @oikarinen

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from argparse import ArgumentParser, Namespace
from typing import Callable, NoReturn, Sequence, TypeVar


import logging

F = TypeVar("F")


# Name of the property to store the arguments
_PROP_NAME = "_cli_commnd_args"


def arg(*args: any, **kwargs: any) -> Callable[[F], F]:
    """Decorator to attach an argument to a command."""

    def decorator(func: F) -> F:
        if not hasattr(func, _PROP_NAME):
            setattr(func, _PROP_NAME, [])
        if args or kwargs:
            getattr(func, _PROP_NAME).append((args, kwargs))
        return func

    return decorator


class CliBase:
    """Base class for the CLI commands."""

    def __init__(self, *, description: str = None) -> None:
        self.log = logging.getLogger(__name__)
        if description is None:
            description = self.__doc__
        self.parser = ArgumentParser(description=description)
        self.subparsers = self.parser.add_subparsers(help="Commands", dest="command")
        self.args = Namespace()

    def main(self, args: Sequence[str] | None = None) -> NoReturn:
        """Main function to parse the command line arguments and execute the command."""
        # Common arguments before commands
        self.parser.add_argument("--debug", help="Enable debug logging", action="store_true")
        self.subparsers_for_commands()

        self.parser.parse_args(namespace=self.args)
        logging.basicConfig(level=logging.DEBUG if self.args.debug else logging.INFO)
        try:
            exit(self.run_command())
        except CliError as e:
            print("Error: %s" % e)
            exit(1)
        except FileNotFoundError as e:
            print("File not found: %s" % e)
            exit(1)
        except KeyboardInterrupt:
            print("Interrupted by user")
            exit(1)
        except NotImplementedError as e:
            print("Feature not implemented: %s" % e)
            exit(1)
        except ValueError as e:
            print("Invalid value: %s" % e)
            exit(1)

    def subparsers_for_commands(self) -> None:
        """Add the commands to the parser."""
        for prop in dir(self):
            func = getattr(self, prop, None)
            if callable(func) and hasattr(func, _PROP_NAME):
                # Command from the function name
                cmd = func.__name__.replace("_", "-")
                # Pull help from docstring
                parser = self.subparsers.add_parser(cmd, description=func.__doc__, help=func.__doc__)
                parser.add_subparsers()
                parser.set_defaults(func=func)
                # Next, pull the args that were attached to the function
                for args, kwargs in getattr(func, _PROP_NAME, []):
                    parser.add_argument(*args, **kwargs)

    def run_command(self) -> int:
        """Run the command."""
        func = getattr(self.args, "func", None)
        if func is None:
            self.parser.print_help()
            return 1
        return func()


class CliError(Exception):
    """Error in the CLI that was expected."""

    pass
