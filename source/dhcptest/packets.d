module dhcptest.packets;

import std.algorithm;
import std.array;
import std.bitmanip;
import std.conv;
import std.exception;
import std.format;
import std.random;
import std.range;
import std.socket;
import std.string;

import dhcptest.formats;
import dhcptest.options;

version (Windows)
	static if (__VERSION__ >= 2067)
		import core.sys.windows.winsock2 : ntohs, htons, ntohl, htonl;
	else
		import std.c.windows.winsock : ntohs, htons, ntohl, htonl;
else
version (Posix)
{
	import core.sys.posix.netdb : ntohs, htons, ntohl, htonl;
	import core.sys.posix.arpa.inet : inet_pton;
}
else
	static assert(false, "Unsupported platform");

version (linux)
{
	import core.sys.linux.sys.socket;
	import core.sys.posix.net.if_ : IF_NAMESIZE;

	enum IFNAMSIZ = IF_NAMESIZE;

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

/// Parse DHCP packet from wire format
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

/// Serialize DHCP packet to wire format
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

/// Generate a DHCP request packet
DHCPPacket generatePacket(
	ubyte[] mac,
	ushort requestSecs,
	uint giaddr,
	string[] requestedOptions,
	string[] sentOptions)
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
		OptionFormat fmt = fmtStr.length ? fmtStr.to!OptionFormat : OptionFormat.unknown;
		if (fmt == OptionFormat.unknown)
			fmt = dhcpOptions.get(opt, DHCPOptionSpec.init).format;
		ubyte[] bytes = parseOption(value, fmt);
		packet.options ~= DHCPOption(opt, bytes);
	}
	if (packet.options.all!(option => option.type != DHCPOptionType.dhcpMessageType))
		packet.options = DHCPOption(DHCPOptionType.dhcpMessageType, [DHCPMessageType.discover]) ~ packet.options;
	return packet;
}

/// Calculate IP checksum
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

/// Build raw packet data with Ethernet/IP/UDP headers (raw socket mode)
static if (is(typeof(AF_PACKET)))
ubyte[] buildRawPacketData(
	ubyte[] dhcpData,
	string targetIP,
	ubyte[] mac,
	ushort clientPort,
	ushort serverPort)
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
	header.ip.tot_len = (header.ip.sizeof + header.udp.sizeof + dhcpData.length).to!ushort.htons;
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
	header.udp.uh_ulen = (header.udp.sizeof + dhcpData.length).to!ushort.htons;

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
	header.udp.uh_sum = ipChecksum(cast(ubyte[])(&udpChecksumData)[0..1] ~ dhcpData);

	return cast(ubyte[])(&header)[0..1] ~ dhcpData;
}

/// Format a DHCP packet as a human-readable string
string formatPacket(
	DHCPPacket packet,
	string printOnlyOption = null,
	scope void delegate(string) onWarning = null)
{
	import std.ascii : isAlpha;

	// If printing only a specific option
	if (printOnlyOption != null && printOnlyOption.length > 0)
	{
		string numStr = printOnlyOption;
		string fmtStr = "";
		if (numStr.endsWith("]"))
		{
			auto numParts = printOnlyOption.findSplit("[");
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
				return formatRawOption(option.data, fmt);
			}
		}

		// Option not found, call warning delegate if provided
		if (onWarning)
			onWarning(format("(No option %s in packet)", opt));
		return "";
	}

	// Format full packet
	auto output = appender!string();
	auto opNames = [1:"BOOTREQUEST",2:"BOOTREPLY"];
	output.formattedWrite!"  op=%s chaddr=%(%02X:%) hops=%d xid=%08X secs=%d flags=%04X\n  ciaddr=%s yiaddr=%s siaddr=%s giaddr=%s sname=%s file=%s\n"(
		opNames.get(packet.header.op, packet.header.op.to!string),
		packet.header.chaddr[0..packet.header.hlen],
		packet.header.hops,
		ntohl(packet.header.xid),
		ntohs(packet.header.secs),
		ntohs(packet.header.flags),
		ip(packet.header.ciaddr),
		ip(packet.header.yiaddr),
		ip(packet.header.siaddr),
		ip(packet.header.giaddr),
		packet.header.sname.ptr.to!string,
		packet.header.file.ptr.to!string,
	);

	output.formattedWrite!"  %d options:\n"(packet.options.length);
	foreach (option; packet.options)
	{
		auto type = cast(DHCPOptionType)option.type;
		output.formattedWrite!"    %s: "(formatDHCPOptionType(type));
		auto fmt = dhcpOptions.get(type, DHCPOptionSpec.init).format;
		output.put(formatOption(option.data, fmt));
		output.put("\n");
	}

	return output.data;
}
