## dhcptest

This is a DHCP test tool. It can send DHCP discover packets, and listen for DHCP replies.

The tool is cross-platform, although you will need to compile it yourself for non-Windows platforms.

The tool is written in the [D Programming Language](http://dlang.org/).

## Download

You can download a compiled Windows executable from my website, [here](http://files.thecybershadow.net/dhcptest/).

## Usage

By default, dhcptest starts in interactive mode.
It will listen for DHCP replies, and allow sending DHCP discover packets using the "d" command.
Type `help` in interactive mode for more information.

If you do not receive any replies, try using the `--bind` option to bind to a specific local interface.

The program can also run in automatic mode if the `--query` switch is specified on the command line.
The program has a number of switches - run `dhcptest --help` to see a list.

An example command line to automatically send a discover packet and explicitly request option 43,
wait for a reply, then print just that option:

    dhcptest --quiet --query --request 43 --print-only 43

Query mode will report the first reply recieved. To automatically send a discover packet and wait for 
all replies before the timeout, use --wait. For additional resilience against dropped packets on busy 
networks, consider using the `--retry` and `--timeout` switches:

    dhcptest --quiet --query --wait --retry 5 --timeout 10

You can spoof the Vendor Class Identifier, or send additional DHCP options with the request packet,
using the `--option` switch:

    dhcptest --query --option "60=Initech Groupware"

See [RFC 2132](http://tools.ietf.org/html/rfc2132) for a list and description of DHCP options.


## License

`dhcptest` is available under the [Boost Software License 1.0](http://www.boost.org/LICENSE_1_0.txt).

## Changelog

### dhcptest v0.6 (TBD)

 * Add `--secs` switch
 * Contributed by [Darren White](https://github.com/DarrenWhite99):
     * Add `--wait` switch
     * The `--print-only` switch now understands output formatting:
       `--print-only "N[hex]"` will output the value as a zero padded hexadecimal string of bytes.
       `--print-only "N[ip]"` will output the value as an IP address.

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
