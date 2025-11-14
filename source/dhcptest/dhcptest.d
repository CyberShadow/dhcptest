/**
 * A DHCP testing tool.
 *
 * License:
 *   Boost Software License 1.0:
 *   http://www.boost.org/LICENSE_1_0.txt
 *
 * Authors:
 *   Vladimir Panteleev <vladimir@thecybershadow.net>
 */

module dhcptest.dhcptest;

import core.thread;

import std.algorithm;
import std.array;
import std.ascii;
import std.bitmanip;
import std.conv;
import std.datetime;
import std.exception;
import std.format;
import std.getopt;
import std.math : ceil;
import std.random;
import std.range;
import std.socket;
import std.stdio;
import std.string;
import std.traits;

import dhcptest.formats;
import dhcptest.options;
import dhcptest.packets;
import dhcptest.network;

version (Windows)
	static if (__VERSION__ >= 2067)
		import core.sys.windows.winsock2 : ntohs, htons, ntohl, htonl;
	else
		import std.c.windows.winsock : ntohs, htons, ntohl, htonl;
else
version (Posix)
	import core.sys.posix.netdb : ntohs, htons, ntohl, htonl;
else
	static assert(false, "Unsupported platform");

__gshared string printOnly;
__gshared bool quiet;

/// Print a DHCP packet to a file
void printPacket(File f, DHCPPacket packet)
{
	// Create warning handler that respects the quiet flag
	void warningHandler(string msg)
	{
		if (!quiet)
			stderr.writefln("%s", msg);
	}

	f.write(formatPacket(packet, printOnly, &warningHandler));
	f.flush();
}

enum SERVER_PORT = 67;
enum CLIENT_PORT = 68;

ushort serverPort = SERVER_PORT;
ushort clientPort = CLIENT_PORT;

string[] requestedOptions;
string[] sentOptions;
ushort requestSecs = 0;
uint giaddr;

/// Wrapper for generatePacket that uses global state
DHCPPacket generatePacketFromGlobals(ubyte[] mac)
{
	try
		return dhcptest.packets.generatePacket(mac, requestSecs, giaddr, requestedOptions, sentOptions);
	catch (Exception e)
	{
		stderr.writeln("Error with parsing option: ", e.msg);
		throw e;
	}
}

int run(string[] args)
{
	string bindAddr = "0.0.0.0";
	string iface = null;
	string target = targetBroadcast;
	string giaddrStr = "0.0.0.0";
	ubyte[] defaultMac = 6.iota.map!(i => i == 0 ? ubyte((uniform!ubyte & 0xFC) | 0x02u) : uniform!ubyte).array;
	bool help, query, wait, raw;
	float timeoutSeconds = 60f;
	uint tries = 1;

	enum forever = 1000.days;

	getopt(args,
		"h|help", &help,
		"bind", &bindAddr,
		"target", &target,
		"bind-port", &clientPort,
		"target-port", &serverPort,
		"giaddr", &giaddrStr,
		"iface", &iface,
		"r|raw", &raw,
		"mac", (string mac, string value) { defaultMac = parseMac(value); },
		"secs", &requestSecs,
		"q|quiet", &quiet,
		"query", &query,
		"wait", &wait,
		"request", &requestedOptions,
		"print-only", &printOnly,
		"timeout", &timeoutSeconds,
		"tries", &tries,
		"option", &sentOptions,
	);

	if (wait) enforce(query, "Option --wait only supported with --query");

	/// https://issues.dlang.org/show_bug.cgi?id=6725
	auto timeout = dur!"hnsecs"(cast(long)(convert!("seconds", "hnsecs")(1) * timeoutSeconds));

	if (!quiet)
	{
		stderr.writeln("dhcptest v0.9 - Created by Vladimir Panteleev");
		stderr.writeln("https://github.com/CyberShadow/dhcptest");
		stderr.writeln("Run with --help for a list of command-line options.");
		stderr.writeln();
	}

	if (help)
	{
		stderr.writeln("Usage: ", args[0], " [OPTION]...");
		stderr.writeln();
		stderr.writeln("Options:");
		stderr.writeln("  --bind IP       Listen on the interface with the specified IP.");
		stderr.writeln("                  The default is to listen on all interfaces (0.0.0.0).");
		stderr.writeln("                  On Linux, you should use --iface instead.");
		stderr.writeln("  --target IP     Instead of sending a broadcast packet, send a normal packet");
		stderr.writeln("                  to this IP.");
		stderr.writeln("  --bind-port N   Listen on and send packets from this port number instead of");
		stderr.writeln("                  the standard %d.".format(CLIENT_PORT));
		stderr.writeln("  --target-port N Send packets to this port instead of the standard %d.".format(SERVER_PORT));
		stderr.writeln("  --giaddr IP     Set giaddr to the specified relay agent IP address.");
		stderr.writeln("  --iface NAME    Bind to the specified network interface name.  Linux only.");
		stderr.writeln("  --raw           Use raw sockets.  Allows spoofing the MAC address in the ");
		stderr.writeln("                  Ethernet header.  Linux only.  Use with --iface.");
		stderr.writeln("  --mac MAC       Specify a MAC address to use for the client hardware");
		stderr.writeln("                  address field (chaddr), in the format NN:NN:NN:NN:NN:NN");
		stderr.writeln("  --secs          Specify the \"Secs\" request field (number of seconds elapsed");
		stderr.writeln("                  since a client began an attempt to acquire or renew a lease)");
		stderr.writeln("  --quiet         Suppress program output except for received data");
		stderr.writeln("                  and error messages");
		stderr.writeln("  --query         Instead of starting an interactive prompt, immediately send");
		stderr.writeln("                  a discover packet, wait for a result, print it and exit.");
		stderr.writeln("  --wait          Wait until timeout elapsed before exiting from --query, all");
		stderr.writeln("                  offers returned will be reported.");
		stderr.writeln("  --option OPTION Add an option to the request packet. The option must be");
		stderr.writeln("                  specified using the syntax CODE=VALUE or CODE[FORMAT]=VALUE,");
		stderr.writeln("                  where CODE is the numeric option number, FORMAT is how the");
		stderr.writeln("                  value is to be interpreted and decoded, and VALUE is the");
		stderr.writeln("                  option value. FORMAT may be omitted for known option CODEs");
		stderr.writeln("                  E.g. to specify a Vendor Class Identifier:");
		stderr.writeln("                  --option \"60=Initech Groupware\"");
		stderr.writeln("                  You can specify hexadecimal or IPv4-formatted options using");
		stderr.writeln("                  --option \"N[hex]=...\" or --option \"N[IP]=...\"");
		stderr.writeln("                  Supported FORMAT types:");
		stderr.write("%-(%s, %)".format(EnumMembers!OptionFormat[1..$].only.uniq).wrap(79,
				/*  */ "                    ",
				/*  */ "                    "));
		stderr.writeln("  --request N     Uses DHCP option 55 (\"Parameter Request List\") to");
		stderr.writeln("                  explicitly request the specified option from the server.");
		stderr.writeln("                  Can be repeated several times to request multiple options.");
		stderr.writeln("  --print-only N  Print only the specified DHCP option.");
		stderr.writeln("                  You can specify a desired format using the syntax N[FORMAT]");
		stderr.writeln("                  See above for a list of FORMATs. For example:");
		stderr.writeln("                  --print-only \"N[hex]\" or --print-only \"N[IP]\"");
		stderr.writeln("  --timeout N     Wait N seconds for a reply, after which retry or exit.");
		stderr.writeln("                  Default is 60 seconds. Can be a fractional number.");
		stderr.writeln("                  A value of 0 causes dhcptest to wait indefinitely.");
		stderr.writeln("  --tries N       Send N DHCP discover packets after each timeout interval.");
		stderr.writeln("                  Specify N=0 to retry indefinitely.");
		return 0;
	}

	// Create and configure sockets
	auto sockets = createSockets(target, serverPort, raw, iface);

	// Parse giaddr
	giaddr = (new InternetAddress(giaddrStr, 0)).addr.htonl();

	void bindSocketWithLogging()
	{
		bindSocket(sockets.receiveSocket, bindAddr, clientPort, iface);
		if (!quiet) stderr.writefln("Listening for DHCP replies on port %d.", clientPort);
	}

	void runPrompt()
	{
		try
			bindSocketWithLogging();
		catch (Exception e)
		{
			stderr.writeln("Error while attempting to bind socket:");
			stderr.writeln(e.msg);
			stderr.writeln("Replies will not be visible. Use a packet capture tool to see replies,");
			stderr.writeln("or try re-running the program with more permissions.");
		}

		void listenThread()
		{
			try
			{
				sockets.receiveSocket.receivePackets((DHCPPacket packet, Address address)
				{
					if (!quiet) stderr.writefln("Received packet from %s:", address);
					stdout.printPacket(packet);
					return true;
				}, forever, (msg) { if (!quiet) stderr.writefln("%s", msg); });
			}
			catch (Exception e)
			{
				stderr.writeln("Error on listening thread:");
				stderr.writeln(e.toString());
			}
		}

		auto t = new Thread(&listenThread);
		t.isDaemon = true;
		t.start();

		if (!quiet) stderr.writeln(`Type "d" to broadcast a DHCP discover packet, or "help" for details.`);
		while (!stdin.eof)
		{
			auto line = readln().strip().split();
			if (!line.length)
			{
				if (!stdin.eof)
					stderr.writeln("Enter a command.");
				continue;
			}

			switch (line[0].toLower())
			{
				case "d":
				case "discover":
				{
					ubyte[] mac = line.length > 1 ? parseMac(line[1]) : defaultMac;
					auto packet = generatePacketFromGlobals(mac);
					if (!quiet)
					{
						stderr.writefln("Sending packet:");
						stderr.printPacket(packet);
					}
					sockets.sendSocket.sendPacket(sockets.sendAddress, target, mac, packet, clientPort, serverPort);
					break;
				}

				case "q":
				case "quit":
				case "exit":
					return;

				case "help":
				case "?":
					stderr.writeln("Commands:");
					stderr.writeln("  d / discover");
					stderr.writeln("        Broadcasts a DHCP discover packet.");
					stderr.writeln("        You can optionally specify a part or an entire MAC address");
					stderr.writeln("        to use for the client hardware address field (chaddr), e.g.");
					stderr.writeln(`        "d 01:23:45" will use the specified first 3 octets and`);
					stderr.writeln(`        randomly generate the rest.`);
					stderr.writeln(`  help`);
					stderr.writeln(`        Print this message.`);
					stderr.writeln(`  q / quit`);
					stderr.writeln(`        Quits the program.`);
					break;
				default:
					stderr.writeln("Unrecognized command.");
			}
		}
	}

	int runQuery()
	{
		if (tries == 0)
			tries = tries.max;
		if (timeout == Duration.zero)
			timeout = forever;

		bindSocketWithLogging();
		auto sentPacket = generatePacketFromGlobals(defaultMac);
		if (!quiet)
		{
			stderr.writefln("Sending packet:");
			stderr.printPacket(sentPacket);
		}

		int count = 0;

		foreach (t; 0..tries)
		{
			if (!quiet && t) stderr.writefln("Retrying, try %d...", t+1);

			SysTime start = Clock.currTime();
			SysTime end = start + timeout;

			sockets.sendSocket.sendPacket(sockets.sendAddress, target, defaultMac, sentPacket, clientPort, serverPort);

			while (true)
			{
				auto remaining = end - Clock.currTime();
				if (remaining <= Duration.zero)
					break;

				auto result = sockets.receiveSocket.receivePackets((DHCPPacket packet, Address address)
				{
					if (packet.header.xid != sentPacket.header.xid)
						return true;
					if (!quiet) stderr.writefln("Received packet from %s:", address);
					stdout.printPacket(packet);
					return false;
				}, remaining, (msg) { if (!quiet) stderr.writefln("%s", msg); });

				if (result && !wait) // Got reply packet and do not wait for all query responses
					return 0;

				if (result) // Got reply packet?
					count++;
			}

			if (count) // Did we get any responses?
				return 0;
		}

		if (!quiet) stderr.writefln("Giving up after %d %s.", tries, tries==1 ? "try" : "tries");
		return 1;
	}

	if (query)
		return runQuery();
	else
	{
		runPrompt();
		return 0;
	}
}

version(unittest) {} else
int main(string[] args)
{
	debug
		return run(args);
	else
	{
		try
			return run(args);
		catch (Exception e)
		{
			stderr.writeln("Fatal error: ", e.msg);
			return 1;
		}
	}
}
