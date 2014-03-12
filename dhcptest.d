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
import std.getopt;
import std.random;
import std.stdio;
import std.string;
import std.socket;

version(Windows)
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
	subnetMask = 1,
	timeOffset = 2,
	router = 3,
	timeServer = 4,
	nameServer = 5,
	domainNameServer = 6,
	domainName = 15,
	netbiosNodeType = 46,
	leaseTime = 51,
	dhcpMessageType = 53,
	serverIdentifier = 54,
	renewalTime = 58,
	rebindingTime = 59,
}

string[ubyte] dhcpOptionNames;
static this()
{
	dhcpOptionNames =
	[
		  0 : "Pad Option",
		  1 : "Subnet Mask",
		  2 : "Time Offset",
		  3 : "Router Option",
		  4 : "Time Server Option",
		  5 : "Name Server Option",
		  6 : "Domain Name Server Option",
		  7 : "Log Server Option",
		  8 : "Cookie Server Option",
		  9 : "LPR Server Option",
		 10 : "Impress Server Option",
		 11 : "Resource Location Server Option",
		 12 : "Host Name Option",
		 13 : "Boot File Size Option",
		 14 : "Merit Dump File",
		 15 : "Domain Name",
		 16 : "Swap Server",
		 17 : "Root Path",
		 18 : "Extensions Path",
		 19 : "IP Forwarding Enable/Disable Option",
		 20 : "Non-Local Source Routing Enable/Disable Option",
		 21 : "Policy Filter Option",
		 22 : "Maximum Datagram Reassembly Size",
		 23 : "Default IP Time-to-live",
		 24 : "Path MTU Aging Timeout Option",
		 25 : "Path MTU Plateau Table Option",
		 26 : "Interface MTU Option",
		 27 : "All Subnets are Local Option",
		 28 : "Broadcast Address Option",
		 29 : "Perform Mask Discovery Option",
		 30 : "Mask Supplier Option",
		 31 : "Perform Router Discovery Option",
		 32 : "Router Solicitation Address Option",
		 33 : "Static Route Option",
		 34 : "Trailer Encapsulation Option",
		 35 : "ARP Cache Timeout Option",
		 36 : "Ethernet Encapsulation Option",
		 37 : "TCP Default TTL Option",
		 38 : "TCP Keepalive Interval Option",
		 39 : "TCP Keepalive Garbage Option",
		 40 : "Network Information Service Domain Option",
		 41 : "Network Information Servers Option",
		 42 : "Network Time Protocol Servers Option",
		 43 : "Vendor Specific Information",
		 44 : "NetBIOS over TCP/IP Name Server Option",
		 45 : "NetBIOS over TCP/IP Datagram Distribution Server Option",
		 46 : "NetBIOS over TCP/IP Node Type Option",
		 47 : "NetBIOS over TCP/IP Scope Option",
		 48 : "X Window System Font Server Option",
		 49 : "X Window System Display Manager Option",
		 50 : "Requested IP Address",
		 51 : "IP Address Lease Time",
		 52 : "Option Overload",
		 53 : "DHCP Message Type",
		 54 : "Server Identifier",
		 55 : "Parameter Request List",
		 56 : "Message",
		 57 : "Maximum DHCP Message Size",
		 58 : "Renewal (T1) Time Value",
		 59 : "Rebinding (T2) Time Value",
		 60 : "Vendor class identifier",
		 61 : "Client-identifier",
		 64 : "Network Information Service+ Domain Option",
		 65 : "Network Information Service+ Servers Option",
		 66 : "TFTP server name",
		 67 : "Bootfile name",
		 68 : "Mobile IP Home Agent option",
		 69 : "Simple Mail Transport Protocol (SMTP) Server Option",
		 70 : "Post Office Protocol (POP3) Server Option",
		 71 : "Network News Transport Protocol (NNTP) Server Option",
		 72 : "Default World Wide Web (WWW) Server Option",
		 73 : "Default Finger Server Option",
		 74 : "Default Internet Relay Chat (IRC) Server Option",
		 75 : "StreetTalk Server Option",
		 76 : "StreetTalk Directory Assistance (STDA) Server Option",
		255 : "End Option",
	];
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
string maybeAscii(ubyte[] bytes)
{
	string s = "%(%02X %)".format(bytes);
	if (bytes.all!(b => b >= 0x20 && b <= 0x7E))
		s ~= " %(%s%)".format([cast(string)bytes]);
	return s;
}

void printPacket(DHCPPacket packet)
{
	auto opNames = [1:"BOOTREQUEST",2:"BOOTREPLY"];
	writefln("  op=%s chaddr=%(%02X:%) hops=%d xid=%08X secs=%d flags=%04X\n  ciaddr=%s yiaddr=%s siaddr=%s giaddr=%s sname=%s file=%s",
		opNames.get(packet.header.op, text(packet.header.op)),
		packet.header.chaddr[0..packet.header.hlen],
		packet.header.hops,
		packet.header.xid,
		ntohs(packet.header.secs),
		ntohs(packet.header.flags),
		ip(packet.header.ciaddr),
		ip(packet.header.yiaddr),
		ip(packet.header.siaddr),
		ip(packet.header.giaddr),
		to!string(packet.header.sname.ptr),
		to!string(packet.header.file.ptr),
	);

	writefln("  %d options:", packet.options.length);
	foreach (option; packet.options)
	{
		auto type = cast(DHCPOptionType)option.type;
		writef("    %3d (%s): ", type, dhcpOptionNames.get(option.type, "Unknown"));
		switch (type)
		{
			case DHCPOptionType.dhcpMessageType:
				enforce(option.data.length==1, "Bad dhcpMessageType data length");
				writeln(cast(DHCPMessageType)option.data[0]);
				break;
			case DHCPOptionType.netbiosNodeType:
				enforce(option.data.length==1, "Bad netbiosNodeType data length");
				writeln(cast(NETBIOSNodeType)option.data[0]);
				break;
			case DHCPOptionType.subnetMask:
			case DHCPOptionType.router:
			case DHCPOptionType.timeServer:
			case DHCPOptionType.nameServer:
			case DHCPOptionType.domainNameServer:
			case DHCPOptionType.serverIdentifier:
				enforce(option.data.length % 4 == 0, "Bad IP option data length");
				writefln("%-(%s, %)", map!ip(cast(uint[])option.data));
				break;
			case DHCPOptionType.domainName:
				writeln(cast(string)option.data);
				break;
			case DHCPOptionType.timeOffset:    // seconds
			case DHCPOptionType.leaseTime:     // seconds
			case DHCPOptionType.renewalTime:
			case DHCPOptionType.rebindingTime:
				enforce(option.data.length % 4 == 0, "Bad integer option data length");
				writefln("%-(%s, %)", map!ntime(cast(uint[])option.data));
				break;
			default:
				writeln(maybeAscii(option.data));
		}
	}
}

enum SERVER_PORT = 67;
enum CLIENT_PORT = 68;

__gshared UdpSocket socket;

void listenThread()
{
	try
	{
		static ubyte[0x10000] buf;
		ptrdiff_t received;
		Address address;
		while ((received = socket.receiveFrom(buf[], address)) > 0)
		{
			auto receivedData = buf[0..received].dup;
			try
			{
				auto packet = parsePacket(receivedData);
				writefln("Received packet from %s:", address);
				printPacket(packet);
			}
			catch (Exception e)
				writefln("Error while parsing packet [%(%02X %)]: %s", receivedData, e.toString());
		}

		throw new Exception("socket.receiveFrom returned %d.".format(received));
	}
	catch (Exception e)
	{
		writeln("Error on listening thread:");
		writeln(e.toString());
	}
}

void sendPacket()
{
	DHCPPacket packet;
	packet.header.op = 1; // BOOTREQUEST
	packet.header.htype = 1;
	packet.header.hlen = 6;
	packet.header.hops = 0;
	packet.header.xid = uniform!uint();
	packet.header.flags = htons(0x8000); // Set BROADCAST flag - required to be able to receive a reply to an imaginary hardware address
	foreach (ref b; packet.header.chaddr[0..packet.header.hlen])
		b = uniform!ubyte();
	packet.options ~= DHCPOption(DHCPOptionType.dhcpMessageType, [DHCPMessageType.discover]);
	writefln("Sending packet:");
	printPacket(packet);
	socket.sendTo(serializePacket(packet), new InternetAddress("255.255.255.255", SERVER_PORT));
}

void main(string[] args)
{
	string bindAddr = "0.0.0.0";
	getopt(args,
		"bind", &bindAddr,
	);

	socket = new UdpSocket();
	socket.setOption(SocketOptionLevel.SOCKET, SocketOption.BROADCAST, 1);
	try
	{
		socket.setOption(SocketOptionLevel.SOCKET, SocketOption.REUSEADDR, 1);
		socket.bind(getAddress(bindAddr, CLIENT_PORT)[0]);
		writefln("Listening for DHCP replies on port %d.", CLIENT_PORT);
	}
	catch (Exception e)
	{
		writeln("Error while attempting to bind socket:");
		writeln(e);
		writeln("Replies will not be visible. Use a packet capture tool to see replies,\nor try re-running the program with more permissions.");
	}

	(new Thread(&listenThread)).start();

	writeln("Type \"d\" to broadcast a DHCP discover packet.");
	while (true)
	{
		auto line = readln().strip().split();
		if (!line.length)
		{
			writeln("Enter a command.");
			continue;
		}

		switch (line[0].toLower())
		{
			case "d":
			case "discover":
				sendPacket();
				break;
			default:
				writeln("Unrecognized command.");
		}
	}
}
