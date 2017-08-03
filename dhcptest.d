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

module dhcptest;

import core.thread;

import std.algorithm;
import std.array;
import std.conv;
import std.datetime;
import std.exception;
import std.getopt;
import std.random;
import std.range;
import std.stdio;
import std.string;
import std.socket;
import std.traits;

version(Windows)
	static if (__VERSION__ >= 2067)
		import core.sys.windows.winsock2 : ntohs, htons, ntohl, htonl;
	else
		import std.c.windows.winsock : ntohs, htons, ntohl, htonl;
else
version(Posix)
	import core.sys.posix.netdb  : ntohs, htons, ntohl, htonl;
else
	static assert(false, "Unsupported platform");

/// Header (part up to the option fields) of a DHCP packet, as on wire.
align(1)
struct DHCPHeader
{
align(1):
	/// Message op code / message type. 1 = BOOTREQUEST, 2 = BOOTREPLY
	ubyte op;

	/// Hardware address type, see ARP section in "Assigned Numbers" RFC; e.g., '1' = 10mb ethernet.
	ubyte htype;

	/// Hardware address length (e.g.  '6' for 10mb ethernet).
	ubyte hlen;

	/// Client sets to zero, optionally used by relay agents when booting via a relay agent.
	ubyte hops;

	/// Transaction ID, a random number chosen by the client, used by the client and server to associate messages and responses between a client and a server.
	uint xid;

	/// Filled in by client, seconds elapsed since client began address acquisition or renewal process.
	ushort secs;

	/// Flags. (Only the BROADCAST flag is defined.)
	ushort flags;

	/// Client IP address; only filled in if client is in BOUND, RENEW or REBINDING state and can respond to ARP requests.
	uint ciaddr;

	/// 'your' (client) IP address.
	uint yiaddr;

	/// IP address of next server to use in bootstrap; returned in DHCPOFFER, DHCPACK by server.
	uint siaddr;

	/// Relay agent IP address, used in booting via a relay agent.
	uint giaddr;

	/// Client hardware address.
	ubyte[16] chaddr;

	/// Optional server host name, null terminated string.
	char[64] sname = 0;

	/// Boot file name, null terminated string; "generic" name or null in DHCPDISCOVER, fully qualified directory-path name in DHCPOFFER.
	char[128] file = 0;

	/// Optional parameters field.  See the options documents for a list of defined options.
	ubyte[0] options;

	static assert(DHCPHeader.sizeof == 236);
}

/*
35 01 02 
0F 17 68 6F 6D 65 2E 74 68 65 63 79 62 65 72 73 68 61 64 6F 77 2E 6E 65 74 
01 04 FF FF FF 00 
06 04 C0 A8 00 01 
03 04 C0 A8 00 01 
05 04 C0 A8 00 01 
36 04 C0 A8 00 01 
33 04 00 00 8C A0 
FF
*/

struct DHCPOption
{
	ubyte type;
	ubyte[] data;
}

struct DHCPPacket
{
	DHCPHeader header;
	DHCPOption[] options;
}

enum DHCPOptionType : ubyte
{
	dhcpMessageType = 53,
	parameterRequestList = 55,
}

enum DHCPMessageType : ubyte
{
	discover = 1,
	offer,
	request,
	decline,
	ack,
	nak,
	release,
	inform
}

enum NETBIOSNodeType : ubyte
{
	bNode = 1,
	pNode,
	mMode,
	hNode
}

/// How option values are displayed and interpreted
enum OptionFormat
{
	none,
	str,
	ip,
	IP = ip, // for backwards compatibility
	hex,
	i32,
	time,
	dhcpMessageType,
	dhcpOptionType,
	netbiosNodeType,
}

struct DHCPOptionSpec
{
	string name;
	OptionFormat format;
}

DHCPOptionSpec[ubyte] dhcpOptions;
static this()
{
	dhcpOptions =
	[
		  0 : DHCPOptionSpec("Pad Option", OptionFormat.none),
		  1 : DHCPOptionSpec("Subnet Mask", OptionFormat.ip),
		  2 : DHCPOptionSpec("Time Offset", OptionFormat.time),
		  3 : DHCPOptionSpec("Router Option", OptionFormat.ip),
		  4 : DHCPOptionSpec("Time Server Option", OptionFormat.ip),
		  5 : DHCPOptionSpec("Name Server Option", OptionFormat.ip),
		  6 : DHCPOptionSpec("Domain Name Server Option", OptionFormat.ip),
		  7 : DHCPOptionSpec("Log Server Option", OptionFormat.none),
		  8 : DHCPOptionSpec("Cookie Server Option", OptionFormat.none),
		  9 : DHCPOptionSpec("LPR Server Option", OptionFormat.none),
		 10 : DHCPOptionSpec("Impress Server Option", OptionFormat.none),
		 11 : DHCPOptionSpec("Resource Location Server Option", OptionFormat.none),
		 12 : DHCPOptionSpec("Host Name Option", OptionFormat.none),
		 13 : DHCPOptionSpec("Boot File Size Option", OptionFormat.none),
		 14 : DHCPOptionSpec("Merit Dump File", OptionFormat.none),
		 15 : DHCPOptionSpec("Domain Name", OptionFormat.str),
		 16 : DHCPOptionSpec("Swap Server", OptionFormat.none),
		 17 : DHCPOptionSpec("Root Path", OptionFormat.none),
		 18 : DHCPOptionSpec("Extensions Path", OptionFormat.none),
		 19 : DHCPOptionSpec("IP Forwarding Enable/Disable Option", OptionFormat.none),
		 20 : DHCPOptionSpec("Non-Local Source Routing Enable/Disable Option", OptionFormat.none),
		 21 : DHCPOptionSpec("Policy Filter Option", OptionFormat.none),
		 22 : DHCPOptionSpec("Maximum Datagram Reassembly Size", OptionFormat.none),
		 23 : DHCPOptionSpec("Default IP Time-to-live", OptionFormat.none),
		 24 : DHCPOptionSpec("Path MTU Aging Timeout Option", OptionFormat.none),
		 25 : DHCPOptionSpec("Path MTU Plateau Table Option", OptionFormat.none),
		 26 : DHCPOptionSpec("Interface MTU Option", OptionFormat.none),
		 27 : DHCPOptionSpec("All Subnets are Local Option", OptionFormat.none),
		 28 : DHCPOptionSpec("Broadcast Address Option", OptionFormat.ip),
		 29 : DHCPOptionSpec("Perform Mask Discovery Option", OptionFormat.none),
		 30 : DHCPOptionSpec("Mask Supplier Option", OptionFormat.none),
		 31 : DHCPOptionSpec("Perform Router Discovery Option", OptionFormat.none),
		 32 : DHCPOptionSpec("Router Solicitation Address Option", OptionFormat.none),
		 33 : DHCPOptionSpec("Static Route Option", OptionFormat.none),
		 34 : DHCPOptionSpec("Trailer Encapsulation Option", OptionFormat.none),
		 35 : DHCPOptionSpec("ARP Cache Timeout Option", OptionFormat.none),
		 36 : DHCPOptionSpec("Ethernet Encapsulation Option", OptionFormat.none),
		 37 : DHCPOptionSpec("TCP Default TTL Option", OptionFormat.none),
		 38 : DHCPOptionSpec("TCP Keepalive Interval Option", OptionFormat.none),
		 39 : DHCPOptionSpec("TCP Keepalive Garbage Option", OptionFormat.none),
		 40 : DHCPOptionSpec("Network Information Service Domain Option", OptionFormat.none),
		 41 : DHCPOptionSpec("Network Information Servers Option", OptionFormat.none),
		 42 : DHCPOptionSpec("Network Time Protocol Servers Option", OptionFormat.ip),
		 43 : DHCPOptionSpec("Vendor Specific Information", OptionFormat.none),
		 44 : DHCPOptionSpec("NetBIOS over TCP/IP Name Server Option", OptionFormat.none),
		 45 : DHCPOptionSpec("NetBIOS over TCP/IP Datagram Distribution Server Option", OptionFormat.none),
		 46 : DHCPOptionSpec("NetBIOS over TCP/IP Node Type Option", OptionFormat.netbiosNodeType),
		 47 : DHCPOptionSpec("NetBIOS over TCP/IP Scope Option", OptionFormat.none),
		 48 : DHCPOptionSpec("X Window System Font Server Option", OptionFormat.none),
		 49 : DHCPOptionSpec("X Window System Display Manager Option", OptionFormat.none),
		 50 : DHCPOptionSpec("Requested IP Address", OptionFormat.none),
		 51 : DHCPOptionSpec("IP Address Lease Time", OptionFormat.time),
		 52 : DHCPOptionSpec("Option Overload", OptionFormat.none),
		 53 : DHCPOptionSpec("DHCP Message Type", OptionFormat.dhcpMessageType),
		 54 : DHCPOptionSpec("Server Identifier", OptionFormat.ip),
		 55 : DHCPOptionSpec("Parameter Request List", OptionFormat.dhcpOptionType),
		 56 : DHCPOptionSpec("Message", OptionFormat.none),
		 57 : DHCPOptionSpec("Maximum DHCP Message Size", OptionFormat.none),
		 58 : DHCPOptionSpec("Renewal (T1) Time Value", OptionFormat.time),
		 59 : DHCPOptionSpec("Rebinding (T2) Time Value", OptionFormat.time),
		 60 : DHCPOptionSpec("Vendor class identifier", OptionFormat.str),
		 61 : DHCPOptionSpec("Client-identifier", OptionFormat.none),
		 64 : DHCPOptionSpec("Network Information Service+ Domain Option", OptionFormat.none),
		 65 : DHCPOptionSpec("Network Information Service+ Servers Option", OptionFormat.none),
		 66 : DHCPOptionSpec("TFTP server name", OptionFormat.str),
		 67 : DHCPOptionSpec("Bootfile name", OptionFormat.str),
		 68 : DHCPOptionSpec("Mobile IP Home Agent option", OptionFormat.none),
		 69 : DHCPOptionSpec("Simple Mail Transport Protocol (SMTP) Server Option", OptionFormat.none),
		 70 : DHCPOptionSpec("Post Office Protocol (POP3) Server Option", OptionFormat.none),
		 71 : DHCPOptionSpec("Network News Transport Protocol (NNTP) Server Option", OptionFormat.none),
		 72 : DHCPOptionSpec("Default World Wide Web (WWW) Server Option", OptionFormat.none),
		 73 : DHCPOptionSpec("Default Finger Server Option", OptionFormat.none),
		 74 : DHCPOptionSpec("Default Internet Relay Chat (IRC) Server Option", OptionFormat.none),
		 75 : DHCPOptionSpec("StreetTalk Server Option", OptionFormat.none),
		 76 : DHCPOptionSpec("StreetTalk Directory Assistance (STDA) Server Option", OptionFormat.none),
		255 : DHCPOptionSpec("End Option", OptionFormat.none),
	];
}

DHCPPacket parsePacket(ubyte[] data)
{
	DHCPPacket result;

	enforce(data.length > DHCPHeader.sizeof + 4, "DHCP packet too small");
	result.header = *cast(DHCPHeader*)data.ptr;
	data = data[DHCPHeader.sizeof..$];

	enforce(data[0..4] == [99, 130, 83, 99], "Absent DHCP option magic cookie");
	data = data[4..$];

	ubyte readByte()
	{
		enforce(data.length, "Unexpected end of packet");
		ubyte result = data[0];
		data = data[1..$];
		return result;
	}

	while (true)
	{
		auto optionType = readByte();
		if (optionType==0) // pad option
			continue;
		if (optionType==255) // end option
			break;

		auto len = readByte();
		DHCPOption option;
		option.type = optionType;
		foreach (n; 0..len)
			option.data ~= readByte();
		result.options ~= option;
	}

	return result;
}

ubyte[] serializePacket(DHCPPacket packet)
{
	ubyte[] data;
	data ~= cast(ubyte[])((&packet.header)[0..1]);
	data ~= [99, 130, 83, 99];
	foreach (option; packet.options)
	{
		data ~= option.type;
		data ~= to!ubyte(option.data.length);
		data ~= option.data;
	}
	data ~= 255;
	return data;
}

string ip(uint addr) { return "%(%d.%)".format(cast(ubyte[])((&addr)[0..1])); }
string ntime(uint n) { return "%d (%s)".format(n.ntohl, n.ntohl.seconds); }
string maybeAscii(in ubyte[] bytes)
{
	string s = "%(%02X %)".format(bytes);
	if (bytes.all!(b => (b >= 0x20 && b <= 0x7E) || !b))
		s = "%(%s, %) (%s)".format((cast(string)bytes).split("\0"), s);
	return s;
}
string formatDHCPOptionType(DHCPOptionType type)
{
	return format("%3d (%s)", cast(ubyte)type, dhcpOptions.get(type, DHCPOptionSpec("Unknown")));
}

__gshared string printOnly;
__gshared bool quiet;

void printOption(File f, in ubyte[] bytes, OptionFormat fmt)
{
	final switch (fmt)
	{
		case OptionFormat.none:
		case OptionFormat.hex:
			f.writeln(maybeAscii(bytes));
			break;
		case OptionFormat.str:
			f.writeln(cast(string)bytes);
			break;
		case OptionFormat.ip:
			enforce(bytes.length % 4 == 0, "Bad IP bytes length");
			f.writefln("%-(%s, %)", map!ip(cast(uint[])bytes));
			break;
		case OptionFormat.i32:
			enforce(bytes.length % 4 == 0, "Bad integer bytes length");
			f.writefln("%-(%s, %)", cast(uint[])bytes);
			break;
		case OptionFormat.time:
			enforce(bytes.length % 4 == 0, "Bad time bytes length");
			f.writefln("%-(%s, %)", map!ntime(cast(uint[])bytes));
			break;
		case OptionFormat.dhcpMessageType:
			enforce(bytes.length==1, "Bad dhcpMessageType data length");
			f.writeln(cast(DHCPMessageType)bytes[0]);
			break;
		case OptionFormat.dhcpOptionType:
			f.writefln("%-(%s, %)", map!formatDHCPOptionType(cast(DHCPOptionType[])bytes));
			break;
		case OptionFormat.netbiosNodeType:
			enforce(bytes.length==1, "Bad netbiosNodeType data length");
			f.writeln(cast(NETBIOSNodeType)bytes[0]);
			break;
	}
}


void printPacket(File f, DHCPPacket packet)
{
	if (printOnly != "")
	{
		ubyte num;
		string fmt = "";
		if (printOnly.endsWith("]"))
		{
			auto numParts = printOnly.findSplit("[");
			fmt = numParts[2][0..$-1];
			num = parse!ubyte(numParts[0]);
		}
		else num = parse!ubyte(printOnly);
		foreach (option; packet.options)
		{
			if (option.type != num) continue;
			switch (fmt.toLower())
			{
				case "":
					f.write(cast(char[])option.data);
					f.flush();
					return;
				case "hex":
					f.writefln("%-(%02X%)", cast(ubyte[])option.data);
					return;
				case "ip":
					f.writefln("%-(%s, %)", map!ip(cast(uint[])option.data));
					return;
				default:
					if (!quiet) stderr.writefln("Unknown format for option %d: %s",num,fmt);
					return;
			}
		}
		if (!quiet) stderr.writefln("(No option %s in packet)", num);
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

ubyte[] requestedOptions;
string[] sentOptions;
ushort requestSecs = 0;

DHCPPacket generatePacket(ubyte[] mac)
{
	DHCPPacket packet;
	packet.header.op = 1; // BOOTREQUEST
	packet.header.htype = 1;
	packet.header.hlen = 6;
	packet.header.hops = 0;
	packet.header.xid = uniform!uint();
	packet.header.secs = requestSecs;
	packet.header.flags = htons(0x8000); // Set BROADCAST flag - required to be able to receive a reply to an imaginary hardware address
	packet.header.chaddr[0..mac.length] = mac;
	foreach (ref b; packet.header.chaddr[mac.length..packet.header.hlen])
		b = uniform!ubyte();
	packet.options ~= DHCPOption(DHCPOptionType.dhcpMessageType, [DHCPMessageType.discover]);
	if (requestedOptions.length)
		packet.options ~= DHCPOption(DHCPOptionType.parameterRequestList, requestedOptions);
	foreach (option; sentOptions)
	{
		scope(failure) stderr.writeln("Error with parsing option ", option, ":");
		auto s = option.findSplit("=");
		string numStr = s[0];
		string value = s[2];
		string fmtStr;
		if (numStr.endsWith("]"))
		{
			auto numParts = numStr.findSplit("[");
			fmtStr = numParts[2][0..$-1];
			numStr = numParts[0];
		}
		auto opt = cast(DHCPOptionType)to!ubyte(numStr);
		ubyte[] bytes;
		OptionFormat fmt = fmtStr.length ? fmtStr.to!OptionFormat : OptionFormat.none;
		if (fmt == OptionFormat.none)
			fmt = dhcpOptions.get(opt, DHCPOptionSpec.init).format;
		final switch (fmt)
		{
			case OptionFormat.none:
				throw new Exception(format("Don't know how to interpret given value for option %d, please specify a format explicitly.", opt));
			case OptionFormat.str:
				bytes = cast(ubyte[])value;
				break;
			case OptionFormat.ip:
				bytes = value
					.replace(" ", ".")
					.replace(",", ".")
					.splitter(".")
					.map!(to!ubyte)
					.array();
				enforce(bytes.length % 4 == 0, "Malformed IP address");
				break;
			case OptionFormat.hex:
				static ubyte fromHex(string os) { auto s = os; ubyte b = s.parse!ubyte(16); enforce(!s.length, "Invalid hex string: " ~ os); return b; }
				bytes = value
					.replace(" ", "")
					.replace(":", "")
					.chunks(2)
					.map!(chunk => fromHex(to!string(chunk)))
					.array();
				break;
			case OptionFormat.i32:
			case OptionFormat.time:
				bytes = value
					.splitter(",")
					.map!strip
					.map!(to!int)
					.map!(i => cast(ubyte[])[i])
					.join();
				break;
			case OptionFormat.dhcpMessageType:
				bytes = value
					.splitter(",")
					.map!strip
					.map!(to!DHCPMessageType)
					.map!((ubyte i) => [i])
					.join();
				break;
			case OptionFormat.dhcpOptionType:
				bytes = value
					.splitter(",")
					.map!strip
					.map!(to!DHCPOptionType)
					.map!((ubyte i) => [i])
					.join();
				break;
			case OptionFormat.netbiosNodeType:
				bytes = value
					.splitter(",")
					.map!strip
					.map!(to!NETBIOSNodeType)
					.map!((ubyte i) => [i])
					.join();
				break;
		}
		packet.options ~= DHCPOption(opt, bytes);
	}
	return packet;
}

void sendPacket(Socket socket, DHCPPacket packet)
{
	if (!quiet)
	{
		stderr.writefln("Sending packet:");
		stderr.printPacket(packet);
	}
	auto data = serializePacket(packet);
	auto sent = socket.sendTo(data, new InternetAddress("255.255.255.255", SERVER_PORT));
	enforce(sent > 0, "sendto error");
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

int run(string[] args)
{
	string bindAddr = "0.0.0.0";
	string defaultMac;
	bool help, query, wait;
	float timeoutSeconds = 0f;
	uint tries = 1;

	enum forever = 1000.days;

	getopt(args,
		"h|help", &help,
		"bind", &bindAddr,
		"mac", &defaultMac,
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
		stderr.writeln("dhcptest v0.6 - Created by Vladimir Panteleev");
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
		stderr.writefln("                  %-(%s, %)", EnumMembers!OptionFormat[1..$].only);
		stderr.writeln("  --request N     Uses DHCP option 55 (\"Parameter Request List\") to");
		stderr.writeln("                  explicitly request the specified option from the server.");
		stderr.writeln("                  Can be repeated several times to request multiple options.");
		stderr.writeln("  --print-only N  Print only the specified DHCP option.");
		stderr.writeln("                  It is assumed to be a text string.");
		stderr.writeln("                  You can specify hexadecimal or IPv4-formatted output using");
		stderr.writeln("                  --print-only \"N[hex]\" or --print-only \"N[IP]\"");
		stderr.writeln("  --timeout N     Wait N seconds for a reply, after which retry or exit.");
		stderr.writeln("                  Default is 10 seconds. Can be a fractional number. ");
		stderr.writeln("  --tries N       Send N DHCP discover packets after each timeout interval.");
		stderr.writeln("                  Specify N=0 to retry indefinitely.");
		return 0;
	}

	auto socket = new UdpSocket();
	socket.setOption(SocketOptionLevel.SOCKET, SocketOption.BROADCAST, 1);

	void bindSocket()
	{
		socket.setOption(SocketOptionLevel.SOCKET, SocketOption.REUSEADDR, 1);
		socket.bind(getAddress(bindAddr, CLIENT_PORT)[0]);
		if (!quiet) stderr.writefln("Listening for DHCP replies on port %d.", CLIENT_PORT);
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
				socket.receivePackets((DHCPPacket packet, Address address)
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
					string mac = line.length > 1 ? line[1] : defaultMac;
					socket.sendPacket(generatePacket(parseMac(mac)));
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
			timeout = (tries == 1 && !wait) ? forever : 10.seconds;

		bindSocket();
		auto sentPacket = generatePacket(parseMac(defaultMac));

		int count = 0;
		
		foreach (t; 0..tries)
		{
			if (!quiet && t) stderr.writefln("Retrying, try %d...", t+1);

			SysTime start = Clock.currTime();
			SysTime end = start + timeout;

			socket.sendPacket(sentPacket);
			
			while (true)
			{
				auto remaining = end - Clock.currTime();
				if (remaining <= Duration.zero)
					break;

				auto result = socket.receivePackets((DHCPPacket packet, Address address)
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
