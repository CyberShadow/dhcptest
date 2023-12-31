## dhcptest

This is a DHCP test tool. It can send DHCP discover packets, and listen for DHCP replies.

The tool is cross-platform, although you will need to compile it yourself for non-Windows platforms.

The tool is written in the [D Programming Language](https://dlang.org/).

## Download

You can download a compiled Windows executable from my website, [here](https://files.cy.md/dhcptest/).

The latest development build for Windows can be downloaded from [GitHub Actions](https://github.com/CyberShadow/dhcptest/actions/workflows/test.yml?query=branch%3Amaster).

## Building

With [DMD](https://dlang.org/download.html#dmd) (or another D compiler) installed, run:

```
$ dmd dhcptest.d
```

## Usage

By default, dhcptest starts in interactive mode.
It will listen for DHCP replies, and allow sending DHCP discover packets using the "d" command.
Type `help` in interactive mode for more information.

If you do not receive any replies, try using the `--bind` option (or `--iface` on Linux) to bind to a specific local interface.

The program can also run in automatic mode if the `--query` switch is specified on the command line.

An example command line to automatically send a discover packet and explicitly request option 43,
wait for a reply, then print just that option:

    dhcptest --quiet --query --request 43 --print-only 43

Options can also be specified by name:

    dhcptest --quiet --query \
         --request    "Vendor Specific Information" \
         --print-only "Vendor Specific Information"

Query mode will report the first reply recieved. To automatically send a discover packet and wait for 
all replies before the timeout, use `--wait`. For additional resilience against dropped packets on busy 
networks, consider using the `--retry` and `--timeout` switches:

    dhcptest --quiet --query --wait --retry 5 --timeout 10

You can spoof the Vendor Class Identifier, or send additional DHCP options with the request packet,
using the `--option` switch:

    dhcptest --query --option "60=Initech Groupware"

Option 82 (Relay Agent Information) can be specified as follows:

    dhcptest --query --option "Relay Agent Information=agentCircuitID=\"foo\", agentRemoteID=\"bar\""

Run `dhcptest --help` for further details and additional command-line parameters.

For a list and description of DHCP options, see [RFC 2132](https://datatracker.ietf.org/doc/html/rfc2132).

## License

`dhcptest` is available under the [Boost Software License 1.0](https://www.boost.org/LICENSE_1_0.txt).

## Changelog

### dhcptest v0.9 (2023-03-31)

 * Add option 121 (contributed by [Andrey Baranov](https://github.com/Dronec))
 * Add options 80, 100, 101, 108, 114, 116, 118, 249, and 252 (contributed by 
   [Rob Gill](https://github.com/rrobgill)
 * Fix encoding/decoding options 43 and 82

### dhcptest v0.8 (2023-03-24)

 * Add `--iface` option for Linux
 * Add support for Linux raw sockets (`--raw`)
 * Add `--bind`, `--target`, and `--target-port` options
 * Add `--giaddr` option (contributed by [pcsegal](https://github.com/pcsegal))
 * Improve formatting and parsing of many options

### dhcptest v0.7 (2017-08-03)

 * Refactor and improve option value parsing
 * Allow specifying all supported format types in both `--option` and
   `--print-only` switches
 * Allow specifying DHCP option types by name as well as by number
 * Allow overriding the request type option. E.g., you can now send
   'request' (instead of 'discover') packets using:

        --option "DHCP Message Type=request"

 * Add formatting support for options 42 (Network Time Protocol
   Servers Option) and 82 (Relay Agent Information)
 * Change how timeouts are handled:
   * Always default to some finite timeout (not just when `--tries`
     and `--wait` are absent), but still allow waiting indefinitely if
     0 is specified.
   * Increase default timeout from 10 to 60 seconds.

### dhcptest v0.6 (2017-08-02)

 * Add `--secs` switch
 * Contributed by [Darren White](https://github.com/DarrenWhite99):
     * Add `--wait` switch
     * The `--print-only` switch now understands output formatting:
       `--print-only "N[hex]"` will output the value as a zero padded hexadecimal string of bytes.
       `--print-only "N[ip]"` will output the value as an IP address.
 * Don't print stack trace on errors

### dhcptest v0.5 (2014-11-26)

 * The `--option` switch now understands hexadecimal or IPv4-dotted-quad formatting:  
   `--option "N[hex]=XX XX XX ..."` or `--option "N[IP]=XXX.XXX.XXX.XXX"`

### dhcptest v0.4 (2014-07-21)

 * Add switches: `--retry`, `--timeout`, `--option`

### dhcptest v0.3 (2014-04-05)

 * Add switches: `--mac`, `--quiet`, `--query`, `--request`, `--print-only`
 * Print program messages to standard error

### dhcptest v0.2 (2014-03-25)

 * License under Boost Software License 1.0
 * Add documentation
 * Add `--help` switch
 * Add `--bind` switch to specify the interface to bind on
 * Print time values in human-readable form
 * Heuristically detect and print ASCII strings in unknown options
 * Add option names from RFC 2132
 * Add `help` and `quit` commands
 * Add MAC address option to `discover` command

### dhcptest v0.1 (2013-01-10)

 * Initial release
