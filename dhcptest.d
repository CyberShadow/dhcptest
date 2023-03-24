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
import std.bitmanip;
import std.conv;
import std.datetime;
import std.exception;
import std.format;
import std.getopt;
import std.random;
import std.range;
import std.stdio;
import std.string;
import std.socket;
import std.traits;

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
	import core.sys.linux.sys.socket;
	import core.sys.posix.net.if_ : IF_NAMESIZE;
	import core.sys.posix.sys.ioctl : ioctl, SIOCGIFINDEX;

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

	extern(C) struct sockaddr_ll
	{
		ushort   sll_family;
		ushort   sll_protocol;
		int      sll_ifindex;
		ushort   sll_hatype;
		ubyte    sll_pkttype;
		ubyte    sll_halen;
		ubyte[8] sll_addr;
	}

	struct ether_header
	{
		ubyte[6] ether_dhost;
		ubyte[6] ether_shost;
		ushort	ether_type;
	}

	struct iphdr
	{
		mixin(bitfields!(
			ubyte, q{ihl}, 4,
			ubyte, q{ver}, 4,
		));
		ubyte tos;
		ushort tot_len;
		ushort id;
		ushort frag_off;
		ubyte ttl;
		ubyte protocol;
		ushort check;
		uint saddr;
		uint daddr;
	}

	struct udphdr
	{
		ushort uh_sport;
		ushort uh_dport;
		ushort uh_ulen;
		ushort uh_sum;
	}

	enum ETH_P_IP = 0x0800;
	enum IP_DF = 0x4000;
}

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
	pNode = 2,
	mMode = 4,
	hNode = 8
}
enum NETBIOSNodeTypeChars = "BPMH";

/// How option values are displayed and interpreted
enum OptionFormat
{
	none,
	str,
	ip,
	IP = ip, // for backwards compatibility
	hex,
	boolean,
	u8,
	u16,
	u32,
	i32 = u32, // for backwards compatibility
	time,
	dhcpMessageType,
	dhcpOptionType,
	netbiosNodeType,
	relayAgent, // RFC 3046
	vendorSpecificInformation,
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
		  7 : DHCPOptionSpec("Log Server Option", OptionFormat.ip),
		  8 : DHCPOptionSpec("Cookie Server Option", OptionFormat.ip),
		  9 : DHCPOptionSpec("LPR Server Option", OptionFormat.ip),
		 10 : DHCPOptionSpec("Impress Server Option", OptionFormat.ip),
		 11 : DHCPOptionSpec("Resource Location Server Option", OptionFormat.ip),
		 12 : DHCPOptionSpec("Host Name Option", OptionFormat.str),
		 13 : DHCPOptionSpec("Boot File Size Option", OptionFormat.u16),
		 14 : DHCPOptionSpec("Merit Dump File", OptionFormat.str),
		 15 : DHCPOptionSpec("Domain Name", OptionFormat.str),
		 16 : DHCPOptionSpec("Swap Server", OptionFormat.ip),
		 17 : DHCPOptionSpec("Root Path", OptionFormat.str),
		 18 : DHCPOptionSpec("Extensions Path", OptionFormat.str),
		 19 : DHCPOptionSpec("IP Forwarding Enable/Disable Option", OptionFormat.boolean),
		 20 : DHCPOptionSpec("Non-Local Source Routing Enable/Disable Option", OptionFormat.boolean),
		 21 : DHCPOptionSpec("Policy Filter Option", OptionFormat.ip),
		 22 : DHCPOptionSpec("Maximum Datagram Reassembly Size", OptionFormat.u16),
		 23 : DHCPOptionSpec("Default IP Time-to-live", OptionFormat.u8),
		 24 : DHCPOptionSpec("Path MTU Aging Timeout Option", OptionFormat.u32),
		 25 : DHCPOptionSpec("Path MTU Plateau Table Option", OptionFormat.u16),
		 26 : DHCPOptionSpec("Interface MTU Option", OptionFormat.u16),
		 27 : DHCPOptionSpec("All Subnets are Local Option", OptionFormat.boolean),
		 28 : DHCPOptionSpec("Broadcast Address Option", OptionFormat.ip),
		 29 : DHCPOptionSpec("Perform Mask Discovery Option", OptionFormat.boolean),
		 30 : DHCPOptionSpec("Mask Supplier Option", OptionFormat.boolean),
		 31 : DHCPOptionSpec("Perform Router Discovery Option", OptionFormat.boolean),
		 32 : DHCPOptionSpec("Router Solicitation Address Option", OptionFormat.ip),
		 33 : DHCPOptionSpec("Static Route Option", OptionFormat.ip),
		 34 : DHCPOptionSpec("Trailer Encapsulation Option", OptionFormat.boolean),
		 35 : DHCPOptionSpec("ARP Cache Timeout Option", OptionFormat.u32),
		 36 : DHCPOptionSpec("Ethernet Encapsulation Option", OptionFormat.boolean),
		 37 : DHCPOptionSpec("TCP Default TTL Option", OptionFormat.u8),
		 38 : DHCPOptionSpec("TCP Keepalive Interval Option", OptionFormat.u32),
		 39 : DHCPOptionSpec("TCP Keepalive Garbage Option", OptionFormat.boolean),
		 40 : DHCPOptionSpec("Network Information Service Domain Option", OptionFormat.str),
		 41 : DHCPOptionSpec("Network Information Servers Option", OptionFormat.ip),
		 42 : DHCPOptionSpec("Network Time Protocol Servers Option", OptionFormat.ip),
		 43 : DHCPOptionSpec("Vendor Specific Information", OptionFormat.vendorSpecificInformation),
		 44 : DHCPOptionSpec("NetBIOS over TCP/IP Name Server Option", OptionFormat.ip),
		 45 : DHCPOptionSpec("NetBIOS over TCP/IP Datagram Distribution Server Option", OptionFormat.ip),
		 46 : DHCPOptionSpec("NetBIOS over TCP/IP Node Type Option", OptionFormat.netbiosNodeType),
		 47 : DHCPOptionSpec("NetBIOS over TCP/IP Scope Option", OptionFormat.str),
		 48 : DHCPOptionSpec("X Window System Font Server Option", OptionFormat.ip),
		 49 : DHCPOptionSpec("X Window System Display Manager Option", OptionFormat.ip),
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
		 64 : DHCPOptionSpec("Network Information Service+ Domain Option", OptionFormat.str),
		 65 : DHCPOptionSpec("Network Information Service+ Servers Option", OptionFormat.ip),
		 66 : DHCPOptionSpec("TFTP server name", OptionFormat.str),
		 67 : DHCPOptionSpec("Bootfile name", OptionFormat.str),
		 68 : DHCPOptionSpec("Mobile IP Home Agent option", OptionFormat.ip),
		 69 : DHCPOptionSpec("Simple Mail Transport Protocol (SMTP) Server Option", OptionFormat.ip),
		 70 : DHCPOptionSpec("Post Office Protocol (POP3) Server Option", OptionFormat.ip),
		 71 : DHCPOptionSpec("Network News Transport Protocol (NNTP) Server Option", OptionFormat.ip),
		 72 : DHCPOptionSpec("Default World Wide Web (WWW) Server Option", OptionFormat.ip),
		 73 : DHCPOptionSpec("Default Finger Server Option", OptionFormat.ip),
		 74 : DHCPOptionSpec("Default Internet Relay Chat (IRC) Server Option", OptionFormat.ip),
		 75 : DHCPOptionSpec("StreetTalk Server Option", OptionFormat.ip),
		 76 : DHCPOptionSpec("StreetTalk Directory Assistance (STDA) Server Option", OptionFormat.ip),
		 82 : DHCPOptionSpec("Relay Agent Information", OptionFormat.relayAgent),
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
		ubyte b = data[0];
		data = data[1..$];
		return b;
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
	return format("%3d (%s)", cast(ubyte)type, dhcpOptions.get(type, DHCPOptionSpec("Unknown")).name);
}
DHCPOptionType parseDHCPOptionType(string type)
{
	if (type.isNumeric)
		return cast(DHCPOptionType)type.to!ubyte;
	foreach (opt, spec; dhcpOptions)
		if (!icmp(spec.name, type))
			return cast(DHCPOptionType)opt;
	throw new Exception("Unknown DHCP option type: " ~ type);
}

struct RelayAgentInformation
{
	struct Suboption
	{
		enum Type
		{
			raw = -1, // Not a real sub-option - used to store slack / unparseable bytes

			agentCircuitID = 1,
			agentRemoteID = 2,
		}
		Type type;
		char[] value;

		this(Type type, inout(char)[] value) inout { this.type = type; this.value = value; }

		this(ref string s)
		{
			enforce(s.formattedRead!"%s"(&type) == 1, "Expected relay agent sub-option type");
			enforce(s.skipOver("="), "Expected = in relay agent sub-option");
			value = s.parseElement!(char[])();
		}

		string toString() const { return format("%s=%(%s%)", type, value.only); }

		const(ubyte)[] toBytes() const pure
		{
			const(ubyte)[] result;
			if (type != Type.raw)
			{
				result ~= type.to!ubyte;
				result ~= (2 + value.representation.length).to!ubyte;
			}
			result ~= value.representation;
			return result;
		}
	}
	Suboption[] suboptions;

	this(inout(ubyte)[] bytes) inout
	{
		inout(Suboption)[] suboptions;
		while (bytes.length >= 2)
		{
			auto len = bytes[1];
			if (len < 2 || len > bytes.length)
				break;
			suboptions ~= inout Suboption(cast(Suboption.Type)bytes[0], cast(inout(char)[])bytes[2..len]);
			bytes = bytes[len..$];
		}
		if (bytes.length)
			suboptions ~= inout Suboption(Suboption.Type.raw, cast(inout(char)[]) bytes);
		this.suboptions = suboptions;
	}

	this(/*ref*/ string s)
	{
		while (s.length)
		{
			suboptions ~= Suboption(s);
			if (s.length)
			{
				enforce(s.skipOver(","), "',' expected");
				while (s.skipOver(" ")) {}
			}
		}
	}

	string toString() const
	{
		return format!"%-(%s, %)"(suboptions);
	}

	const(ubyte)[] toBytes() const pure
	{
		return suboptions.map!((ref suboption) => suboption.toBytes).join();
	}
}

unittest
{
	void test(ubyte[] bytes, string str)
	{
		auto fromBytes = RelayAgentInformation(bytes);
		assert(fromBytes.toBytes() == bytes, [fromBytes.toBytes(), bytes].to!string);
		assert(fromBytes.toString() == str, [fromBytes.toString(), str].to!string);
		auto fromStr = RelayAgentInformation(str);
		assert(fromStr.toBytes() == bytes);
		assert(fromStr.toString() == str);
	}

	test(
		[],
		``
	);
	test(
		[0x00],
		`raw="\0"`
	);
	test(
		[0x01, 0x05, 'f', 'o', 'o'],
		`agentCircuitID="foo"`
	);
	test(
		[0x01, 0x05, 'f', 'o', 'o', 0x42],
		`agentCircuitID="foo", raw="B"`
	);
	test(
		[0x01, 0x05, 'f', 'o', 'o', 0x02, 0x05, 'b', 'a', 'r'],
		`agentCircuitID="foo", agentRemoteID="bar"`
	);
}

__gshared string printOnly;
__gshared bool quiet;

/// Print an option in a human-readable format.
void printOption(File f, in ubyte[] bytes, OptionFormat fmt)
{
	try
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
			case OptionFormat.boolean:
				f.writefln("%-(%s, %)", cast(bool[])bytes);
				break;
			case OptionFormat.u8:
				f.writefln("%-(%s, %)", bytes);
				break;
			case OptionFormat.u16:
				enforce(bytes.length % 2 == 0, "Bad u16 bytes length");
				f.writefln("%-(%s, %)", (cast(ushort[])bytes).map!ntohs);
				break;
			case OptionFormat.u32:
				enforce(bytes.length % 4 == 0, "Bad u32 bytes length");
				f.writefln("%-(%s, %)", (cast(uint[])bytes).map!ntohl);
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
				f.writefln("%-(%s, %)", bytes
					.map!(b =>
						NETBIOSNodeTypeChars
						.length
						.iota
						.filter!(i => (1 << i) & b)
						.map!(i => NETBIOSNodeTypeChars[i])
						.array
					)
				);
				break;
			case OptionFormat.vendorSpecificInformation:
			{
				const(ubyte)[] rem = bytes;
				while (rem.length)
				{
					enforce(rem.length >= 2, "No length byte");
					auto type = rem[0];
					auto len = rem[1];
					rem = rem[2 .. $];
					enforce(rem.length >= len, "Not enough data");
					auto data = rem[0 .. len];
					rem = rem[len .. $];
					f.writef("%d: %s",
						type, maybeAscii(data));
					if (rem.length)
						f.write(", ");
				}
				f.writeln();
				break;
			}
			case OptionFormat.relayAgent:
				f.writeln((const RelayAgentInformation(bytes)).toString());
				break;
		}
	catch (Exception e)
		f.writefln("Decode error (%s). Raw bytes: %s",
			e.msg, maybeAscii(bytes));
}

/// Print an option in machine-readable format.
void printRawOption(File f, in ubyte[] bytes, OptionFormat fmt)
{
	final switch (fmt)
	{
		case OptionFormat.none:
		case OptionFormat.hex:
		case OptionFormat.relayAgent:
		case OptionFormat.vendorSpecificInformation:
			f.writefln("%-(%02X%)", bytes);
			break;
		case OptionFormat.str:
			f.write(cast(char[])bytes);
			f.flush();
			break;
		case OptionFormat.ip:
		case OptionFormat.boolean:
		case OptionFormat.u8:
		case OptionFormat.u16:
		case OptionFormat.u32:
		case OptionFormat.dhcpMessageType:
		case OptionFormat.dhcpOptionType:
		case OptionFormat.netbiosNodeType:
			return printOption(f, bytes, fmt);
		case OptionFormat.time:
			return printOption(f, bytes, OptionFormat.u32);
	}
}

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

		OptionFormat fmt = fmtStr.length ? fmtStr.to!OptionFormat : OptionFormat.none;
		if (fmt == OptionFormat.none)
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

DHCPPacket generatePacket(ubyte[] mac)
{
	DHCPPacket packet;
	packet.header.op = 1; // BOOTREQUEST
	packet.header.htype = 1;
	packet.header.hlen = mac.length.to!ubyte;
	packet.header.hops = 0;
	packet.header.xid = uniform!uint();
	packet.header.secs = requestSecs;
	packet.header.flags = htons(0x8000); // Set BROADCAST flag - required to be able to receive a reply to an imaginary hardware address
	packet.header.chaddr[0..mac.length] = mac;
	packet.header.giaddr = giaddr;
	if (requestedOptions.length)
		packet.options ~= DHCPOption(DHCPOptionType.parameterRequestList, cast(ubyte[])requestedOptions.map!parseDHCPOptionType.array);
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
		auto opt = parseDHCPOptionType(numStr);
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
			case OptionFormat.boolean:
				bytes = value
					.splitter(",")
					.map!strip
					.map!(to!bool)
					.map!(b => ubyte(b))
					.array();
				break;
			case OptionFormat.u8:
				bytes = value
					.splitter(",")
					.map!strip
					.map!(to!ubyte)
					.array();
				break;
			case OptionFormat.u16:
				bytes = value
					.splitter(",")
					.map!strip
					.map!(to!ushort)
					.map!htons
					.map!((ushort i) { ushort[] a = [i]; ubyte[] b = cast(ubyte[])a; return b; })
					.join();
				break;
			case OptionFormat.u32:
			case OptionFormat.time:
				bytes = value
					.splitter(",")
					.map!strip
					.map!(to!int)
					.map!htonl
					.map!((int i) { int[] a = [i]; ubyte[] b = cast(ubyte[])a; return b; })
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
					.map!parseDHCPOptionType
					.map!((ubyte i) => [i])
					.join();
				break;
			case OptionFormat.netbiosNodeType:
				bytes = value
					.splitter(",")
					.map!strip
					.map!(s => s
						.map!(c => NETBIOSNodeTypeChars.indexOf(c))
						.map!(i => (1 << i).to!ubyte)
						.fold!((a, b) => ubyte(a | b))
					)
					.array();
				break;
			case OptionFormat.relayAgent:
				bytes = RelayAgentInformation(value).toBytes().dup;
				break;
			case OptionFormat.vendorSpecificInformation:
				throw new Exception(format("Sorry, the format %s is unsupported for parsing. Please specify another format explicitly.", fmt));
		}
		packet.options ~= DHCPOption(opt, bytes);
	}
	if (packet.options.all!(option => option.type != DHCPOptionType.dhcpMessageType))
		packet.options = DHCPOption(DHCPOptionType.dhcpMessageType, [DHCPMessageType.discover]) ~ packet.options;
	return packet;
}

ushort ipChecksum(void[] data)
{
	if (data.length % 2)
		data.length = data.length + 1;
	auto words = cast(ushort[])data;
	uint checksum = 0xffff;

	foreach (word; words)
	{
		checksum += ntohs(word);
		if (checksum > 0xffff)
			checksum -= 0xffff;
	}

    return htons((~checksum) & 0xFFFF);
}

void sendPacket(Socket socket, Address addr, string targetIP, ubyte[] mac, DHCPPacket packet)
{
	if (!quiet)
	{
		stderr.writefln("Sending packet:");
		stderr.printPacket(packet);
	}
	auto data = serializePacket(packet);
	static if (is(typeof(AF_PACKET)))
	if (socket.addressFamily != AF_INET)
	{
		static struct Header
		{
		align(1):
			ether_header ether;
			iphdr ip;
			udphdr udp;
		}
		Header header;
		header.ether.ether_dhost[] = 0xFF; // broadcast
		header.ether.ether_shost[] = mac;
		header.ether.ether_type = ETH_P_IP.htons;
		static assert(iphdr.sizeof % 4 == 0);
		header.ip.ihl = iphdr.sizeof / 4;
		header.ip.ver = 4;
		header.ip.tot_len = (header.ip.sizeof + header.udp.sizeof + data.length).to!ushort.htons;
		static ushort idCounter;
		header.ip.id = ++idCounter;
	//	header.ip.frag_off = IP_DF.htons;
		header.ip.ttl = 0x40;
		header.ip.protocol = IPPROTO_UDP;
		header.ip.saddr = 0x00000000; // 0.0.0.0
		inet_pton(AF_INET, targetIP.toStringz, &header.ip.daddr).enforce("Invalid target IP address");
		header.ip.check = ipChecksum((&header.ip)[0..1]);

		header.udp.uh_sport = clientPort.htons;
		header.udp.uh_dport = serverPort.htons;
		header.udp.uh_ulen = (header.udp.sizeof + data.length).to!ushort.htons;

		static struct UDPChecksumData
		{
			uint saddr;
			uint daddr;
			ubyte zeroes = 0x0;
			ubyte proto = IPPROTO_UDP;
			ushort udp_len;
			udphdr udp;
		}
		UDPChecksumData udpChecksumData;
		udpChecksumData.saddr = header.ip.saddr;
		udpChecksumData.daddr = header.ip.daddr;
		udpChecksumData.udp_len = header.udp.uh_ulen;
		udpChecksumData.udp = header.udp;
		header.udp.uh_sum = ipChecksum(cast(ubyte[])(&udpChecksumData)[0..1] ~ data);

		data = cast(ubyte[])(&header)[0..1] ~ data;
		// static import std.file; std.file.write("packet.bin", "000000 %(%02x %|%)".format(data));
	}

	auto sent = socket.sendTo(data, addr);
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
		stderr.writeln("dhcptest v0.7 - Created by Vladimir Panteleev");
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
					sendSocket.sendPacket(sendAddr, target, mac, generatePacket(mac));
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
		auto sentPacket = generatePacket(defaultMac);

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
