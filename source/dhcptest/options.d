module dhcptest.options;

import std.algorithm;
import std.array;
import std.ascii;
import std.conv;
import std.exception : enforce;
import std.format;
import std.range;
import std.string;
import std.traits;

import dhcptest.formats;

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
		  0 : DHCPOptionSpec("Pad Option", OptionFormat.special),
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
		 50 : DHCPOptionSpec("Requested IP Address", OptionFormat.ip),
		 51 : DHCPOptionSpec("IP Address Lease Time", OptionFormat.time),
		 52 : DHCPOptionSpec("Option Overload", OptionFormat.clientIdentifier),
		 53 : DHCPOptionSpec("DHCP Message Type", OptionFormat.dhcpMessageType),
		 54 : DHCPOptionSpec("Server Identifier", OptionFormat.ip),
		 55 : DHCPOptionSpec("Parameter Request List", OptionFormat.dhcpOptionType),
		 56 : DHCPOptionSpec("Message", OptionFormat.str),
		 57 : DHCPOptionSpec("Maximum DHCP Message Size", OptionFormat.u16),
		 58 : DHCPOptionSpec("Renewal (T1) Time Value", OptionFormat.time),
		 59 : DHCPOptionSpec("Rebinding (T2) Time Value", OptionFormat.time),
		 60 : DHCPOptionSpec("Vendor class identifier", OptionFormat.str),
		 61 : DHCPOptionSpec("Client-identifier", OptionFormat.u8),
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
		 77 : DHCPOptionSpec("User-Class-Identifier", OptionFormat.str),
		 80 : DHCPOptionSpec("Rapid Commit", OptionFormat.zeroLength),
		 82 : DHCPOptionSpec("Relay Agent Information", OptionFormat.relayAgent),
		100 : DHCPOptionSpec("PCode", OptionFormat.str),
		101 : DHCPOptionSpec("TCode", OptionFormat.str),
		108 : DHCPOptionSpec("IPv6-Only Preferred", OptionFormat.u32),
		114 : DHCPOptionSpec("DHCP Captive-Portal", OptionFormat.str),
		116 : DHCPOptionSpec("Auto Config", OptionFormat.boolean),
		118 : DHCPOptionSpec("Subnet Selection", OptionFormat.ip),
		121 : DHCPOptionSpec("Classless Static Route Option", OptionFormat.classlessStaticRoute),
		249 : DHCPOptionSpec("Microsoft Classless Static Route", OptionFormat.classlessStaticRoute),
		252 : DHCPOptionSpec("Web Proxy Auto-Discovery", OptionFormat.str),
		255 : DHCPOptionSpec("End Option", OptionFormat.special),
	];
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

// Length-prefixed sub-option list
struct VLList(Type)
{
	struct Suboption
	{
		Type type;
		char[] value;

		this(Type type, inout(char)[] value) inout { this.type = type; this.value = value; }

		this(ref string s)
		{
			assert(s.length);
			if (s[0].isDigit)
			{
				ubyte typeByte;
				enforce(s.formattedRead!"%s"(&typeByte) == 1, "Expected sub-option type");
				type = cast(Type)typeByte;
			}
			else
				enforce(s.formattedRead!"%s"(&type) == 1, "Expected sub-option type");

			enforce(s.skipOver("="), "Expected = in sub-option");
			value = s.parseElement!(char[])();
		}

		string toString() const
		{
			return format("%s=%(%s%)",
				type.to!string.startsWith("cast(") ? type.to!ubyte.to!string : type.to!string,
				value.only);
		}

		const(ubyte)[] toBytes() const pure
		{
			const(ubyte)[] result;
			if (type != Type.raw)
			{
				result ~= type.to!ubyte;
				result ~= value.representation.length.to!ubyte;
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
			if (2 + len > bytes.length)
				break;
			suboptions ~= inout Suboption(cast(Type)bytes[0], cast(inout(char)[])bytes[2 .. 2 + len]);
			bytes = bytes[2 + len .. $];
		}
		if (bytes.length)
			suboptions ~= inout Suboption(Type.raw, cast(inout(char)[]) bytes);
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

enum RelayAgentInformationSuboption
{
	raw = -1, // Not a real sub-option - used to store slack / unparseable bytes

	agentCircuitID = 1,
	agentRemoteID = 2,
}

alias RelayAgentInformation = VLList!RelayAgentInformationSuboption;

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
		[0x01, 0x03, 'f', 'o', 'o'],
		`agentCircuitID="foo"`
	);
	test(
		[0x01, 0x03, 'f', 'o', 'o', 0x42],
		`agentCircuitID="foo", raw="B"`
	);
	test(
		[0x01, 0x03, 'f', 'o', 'o', 0x02, 0x03, 'b', 'a', 'r'],
		`agentCircuitID="foo", agentRemoteID="bar"`
	);
	test(
		[0x03, 0x03, 'f', 'o', 'o'],
		`3="foo"`
	);
}

enum VendorSpecificInformationSuboption
{
	raw = -1, // Not a real sub-option - used to store slack / unparseable bytes
}

alias VendorSpecificInformation = VLList!VendorSpecificInformationSuboption;
