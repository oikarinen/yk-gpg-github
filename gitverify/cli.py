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
from enum import IntEnum
from typing import Callable, NoReturn, Sequence, TypeVar


import logging

F = TypeVar("F")


class ExitCode(IntEnum):
    """Standard exit codes for CLI command completion.

    Following Unix conventions, exit code 0 indicates success.
    Non-zero codes indicate various types of failures or special conditions.

    Attributes:
        SUCCESS (0): Command completed successfully
        FAILURE (1): General command failure
        INVALID_VALUE (11): Invalid argument or parameter value provided
        FILE_NOT_FOUND (12): Required file or directory not found
        INTERRUPTED (21): Command was interrupted (e.g., Ctrl+C)
        LOAD_ERROR (22): Failed to load required resources or configuration
        RUNTIME (23): Runtime error during command execution
        NOT_IMPLEMENTED (99): Requested feature is not implemented
    """
    SUCCESS = 0
    FAILURE = 1
    INVALID_VALUE = 11
    FILE_NOT_FOUND = 12
    INTERRUPTED = 21
    LOAD_ERROR = 22
    RUNTIME = 23
    NOT_IMPLEMENTED = 99


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
    """Base class for command-line interface implementations.

    Provides common functionality for building CLI applications including:
    - Argument parsing with subcommands
    - Logging configuration
    - Exception handling with appropriate exit codes
    - Command registration and execution

    Subclasses should implement command methods decorated with @arg decorators
    and override subparsers_for_commands() if needed.

    Attributes:
        parser: Main argument parser instance
        subparsers: Subcommand parser collection
        args: Parsed command-line arguments namespace
        log: Logger instance for this class
    """

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
        self.parser.add_argument("--config", help="Path to YAML configuration file")
        self.subparsers_for_commands()

        self.parser.parse_args(namespace=self.args)
        logging.basicConfig(level=logging.DEBUG if self.args.debug else logging.INFO)

        # Reload configuration if config file specified
        if hasattr(self.args, 'config') and self.args.config:
            from .common import reload_config
            reload_config(self.args.config)
        try:
            exit(self.run_command())
        except CliError as e:
            self.log.error("Error: %s", e)
            exit(ExitCode.FAILURE)
        except FileNotFoundError as e:
            self.log.error("File not found: %s", e)
            exit(ExitCode.FILE_NOT_FOUND)
        except KeyboardInterrupt:
            self.log.error("Interrupted by user")
            exit(ExitCode.INTERRUPTED)
        except RuntimeError as e:
            self.log.error("Runtime error: %s", e)
            exit(ExitCode.RUNTIME)
        except NotImplementedError as e:
            self.log.error("Feature not implemented: %s", e)
            exit(ExitCode.NOT_IMPLEMENTED)
        except ValueError as e:
            self.log.error("Invalid value: %s", e)
            exit(ExitCode.INVALID_VALUE)

    def subparsers_for_commands(self) -> None:
        """Add the commands to the parser."""
        for prop in dir(self):
            func = getattr(self, prop, None)
            if callable(func) and hasattr(func, _PROP_NAME):
                # Command from the function name
                cmd = func.__name__.replace("_", "-")
                # Pull help from docstring
                parser = self.subparsers.add_parser(cmd, description=func.__doc__, help=func.__doc__)
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
    """Exception raised for expected CLI errors.

    This exception is used for errors that are anticipated during normal CLI
    operation and should be handled gracefully by the CliBase.main() method.
    Examples include invalid user input, missing files, or configuration errors.

    Unlike unexpected exceptions (like programming errors), CliError instances
    result in user-friendly error messages and appropriate exit codes.
    """

    pass
