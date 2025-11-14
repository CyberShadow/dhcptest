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

version (linux)
{
	import core.sys.posix.sys.ioctl : ioctl, SIOCGIFINDEX;
	import core.sys.posix.net.if_ : IF_NAMESIZE;

	enum IFNAMSIZ = IF_NAMESIZE;
	extern(C) struct ifreq
	{
		char[IFNAMSIZ] ifr_name = 0;
		union
		{
			private ubyte[IFNAMSIZ] _zeroinit = 0;
			sockaddr       ifr_addr;
			sockaddr       ifr_dstaddr;
			sockaddr       ifr_broadaddr;
			sockaddr       ifr_netmask;
			sockaddr       ifr_hwaddr;
			short          ifr_flags;
			int            ifr_ifindex;
			int            ifr_metric;
			int            ifr_mtu;
		//	ifmap          ifr_map;
			char[IFNAMSIZ] ifr_slave;
			char[IFNAMSIZ] ifr_newname;
			char*          ifr_data;
		}
	}
}

__gshared string printOnly;
__gshared bool quiet;

void printPacket(File f, DHCPPacket packet)
{
	if (printOnly != "")
	{
		string numStr = printOnly;
		string fmtStr = "";
		if (numStr.endsWith("]"))
		{
			auto numParts = printOnly.findSplit("[");
			fmtStr = numParts[2][0..$-1];
			numStr = numParts[0];
		}
		auto opt = parseDHCPOptionType(numStr);

		OptionFormat fmt = fmtStr.length ? fmtStr.to!OptionFormat : OptionFormat.unknown;
		if (fmt == OptionFormat.unknown)
			fmt = dhcpOptions.get(opt, DHCPOptionSpec.init).format;

		foreach (option; packet.options)
		{
			if (option.type == opt)
			{
				printRawOption(f, option.data, fmt);
				return;
			}
		}
		if (!quiet) stderr.writefln("(No option %s in packet)", opt);
		return;
	}


	auto opNames = [1:"BOOTREQUEST",2:"BOOTREPLY"];
	f.writefln("  op=%s chaddr=%(%02X:%) hops=%d xid=%08X secs=%d flags=%04X\n  ciaddr=%s yiaddr=%s siaddr=%s giaddr=%s sname=%s file=%s",
		opNames.get(packet.header.op, text(packet.header.op)),
		packet.header.chaddr[0..packet.header.hlen],
		packet.header.hops,
		ntohl(packet.header.xid),
		ntohs(packet.header.secs),
		ntohs(packet.header.flags),
		ip(packet.header.ciaddr),
		ip(packet.header.yiaddr),
		ip(packet.header.siaddr),
		ip(packet.header.giaddr),
		to!string(packet.header.sname.ptr),
		to!string(packet.header.file.ptr),
	);

	f.writefln("  %d options:", packet.options.length);
	foreach (option; packet.options)
	{
		auto type = cast(DHCPOptionType)option.type;
		f.writef("    %s: ", formatDHCPOptionType(type));
		auto format = dhcpOptions.get(type, DHCPOptionSpec.init).format;
		printOption(f, option.data, format);
	}

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

void sendPacket(Socket socket, Address addr, string targetIP, ubyte[] mac, DHCPPacket packet)
{
	if (!quiet)
	{
		stderr.writefln("Sending packet:");
		stderr.printPacket(packet);
	}
	auto data = serializePacket(packet);

	// For raw sockets (Linux), wrap DHCP data in Ethernet/IP/UDP headers
	version(linux)
	{
		static if (is(typeof(AF_PACKET)))
		if (socket.addressFamily != AF_INET)
		{
			data = buildRawPacketData(data, targetIP, mac, clientPort, serverPort);
		}
	}

	auto sent = socket.sendTo(data, addr);
	errnoEnforce(sent > 0, "sendto error");
	enforce(sent == data.length, "Sent only %d/%d bytes".format(sent, data.length));
}

bool receivePackets(Socket socket, bool delegate(DHCPPacket, Address) handler, Duration timeout)
{
	static ubyte[0x10000] buf;
	Address address;

	SysTime start = Clock.currTime();
	SysTime end = start + timeout;
	auto set = new SocketSet(1);

	while (true)
	{
		auto remaining = end - Clock.currTime();
		if (remaining <= Duration.zero)
			break;

		set.reset();
		set.add(socket);
		int n = Socket.select(set, null, null, remaining);
		enforce(n >= 0, "select interrupted");
		if (!n)
			break; // timeout exceeded

		auto received = socket.receiveFrom(buf[], address);
		if (received <= 0)
			throw new Exception("socket.receiveFrom returned %d.".format(received));

		auto receivedData = buf[0..received].dup;
		try
		{
			auto result = handler(parsePacket(receivedData), address);
			if (!result)
				return true;
		}
		catch (Exception e)
			stderr.writefln("Error while parsing packet [%(%02X %)]: %s", receivedData, e.toString());
	}

	// timeout exceeded
	if (!quiet) stderr.writefln("Timed out after %s.", timeout);
	return false;
}

ubyte[] parseMac(string mac)
{
	return mac.split(":").map!(s => s.parse!ubyte(16)).array();
}

version(linux) int getIfaceIndex(Socket s, string name)
{
	ifreq req;
	auto len = min(name.length, req.ifr_name.length);
	req.ifr_name[0 .. len] = name[0 .. len];
	errnoEnforce(ioctl(s.handle, SIOCGIFINDEX, &req) == 0, "SIOCGIFINDEX failed");
	return req.ifr_ifindex;
}

immutable targetBroadcast = "255.255.255.255";

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

	auto receiveSocket = new UdpSocket();
	if (target == targetBroadcast)
		receiveSocket.setOption(SocketOptionLevel.SOCKET, SocketOption.BROADCAST, 1);
	Socket sendSocket;
	Address sendAddr;
	if (raw)
	{
		static if (is(typeof(AF_PACKET)))
		{
			sendSocket = new Socket(cast(AddressFamily)AF_PACKET, SocketType.RAW, ProtocolType.RAW);

			enforce(iface, "Interface not specified, please specify an interface with --iface");
			auto ifaceIndex = getIfaceIndex(sendSocket, iface);

			enum ETH_ALEN = 6;
			auto llAddr = new sockaddr_ll;
			llAddr.sll_ifindex = ifaceIndex;
			llAddr.sll_halen = ETH_ALEN;
			llAddr.sll_addr[0 .. 6] = 0xFF;
			sendAddr = new UnknownAddressReference(cast(sockaddr*)llAddr, sockaddr_ll.sizeof);
		}
		else
			throw new Exception("Raw sockets are not supported on this platform.");
	}
	else
	{
		sendSocket = receiveSocket;
		sendAddr = new InternetAddress(target, serverPort);
	}

	// Parse giaddr
	giaddr = (new InternetAddress(giaddrStr, 0)).addr.htonl();

	void bindSocket()
	{
		version (linux)
		{
			if (iface)
			{
				enum SO_BINDTODEVICE = cast(SocketOption)25;
				receiveSocket.setOption(SocketOptionLevel.SOCKET, SO_BINDTODEVICE, cast(void[])iface);
			}
		}
		else
			enforce(iface is null, "--iface is not available on this platform");

		receiveSocket.setOption(SocketOptionLevel.SOCKET, SocketOption.REUSEADDR, 1);
		receiveSocket.bind(getAddress(bindAddr, clientPort)[0]);
		if (!quiet) stderr.writefln("Listening for DHCP replies on port %d.", clientPort);
	}

	void runPrompt()
	{
		try
			bindSocket();
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
				receiveSocket.receivePackets((DHCPPacket packet, Address address)
				{
					if (!quiet) stderr.writefln("Received packet from %s:", address);
					stdout.printPacket(packet);
					return true;
				}, forever);
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
					sendSocket.sendPacket(sendAddr, target, mac, generatePacketFromGlobals(mac));
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

		bindSocket();
		auto sentPacket = generatePacketFromGlobals(defaultMac);

		int count = 0;

		foreach (t; 0..tries)
		{
			if (!quiet && t) stderr.writefln("Retrying, try %d...", t+1);

			SysTime start = Clock.currTime();
			SysTime end = start + timeout;

			sendSocket.sendPacket(sendAddr, target, defaultMac, sentPacket);

			while (true)
			{
				auto remaining = end - Clock.currTime();
				if (remaining <= Duration.zero)
					break;

				auto result = receiveSocket.receivePackets((DHCPPacket packet, Address address)
				{
					if (packet.header.xid != sentPacket.header.xid)
						return true;
					if (!quiet) stderr.writefln("Received packet from %s:", address);
					stdout.printPacket(packet);
					return false;
				}, remaining);

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
