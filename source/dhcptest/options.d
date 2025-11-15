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

/// Processor Architecture Types (RFC 4578, RFC 5970)
/// Used in DHCP Option 93 (Client System Architecture Type)
enum ProcessorArchitecture : ushort
{
	x86BiosInt13h = 0,          // x86 BIOS
	necPC98 = 1,                // NEC/PC98 (DEPRECATED)
	ia64 = 2,                   // Itanium
	decAlpha = 3,               // DEC Alpha (DEPRECATED)
	arcX86 = 4,                 // Arc x86 (DEPRECATED)
	intelLeanClient = 5,        // Intel Lean Client (DEPRECATED)
	x86Uefi = 6,                // x86 UEFI
	x64Uefi = 7,                // x64 UEFI
	efiXscale = 8,              // EFI Xscale (DEPRECATED)
	ebc = 9,                    // EFI Byte Code
	arm32Uefi = 10,             // ARM 32-bit UEFI
	arm64Uefi = 11,             // ARM 64-bit UEFI
	powerPCOpenFirmware = 12,   // PowerPC Open Firmware
	powerPCEpapr = 13,          // PowerPC ePAPR
	powerOpalV3 = 14,           // POWER OPAL v3
	x86UefiHttp = 15,           // x86 UEFI HTTP
	x64UefiHttp = 16,           // x64 UEFI HTTP
	ebcHttp = 17,               // EBC HTTP
	arm32UefiHttp = 18,         // ARM 32-bit UEFI HTTP
	arm64UefiHttp = 19,         // ARM 64-bit UEFI HTTP
	pcBiosHttp = 20,            // PC BIOS HTTP
	arm32Uboot = 21,            // ARM 32-bit u-boot
	arm64Uboot = 22,            // ARM 64-bit u-boot
	arm32UbootHttp = 23,        // ARM 32-bit u-boot HTTP
	arm64UbootHttp = 24,        // ARM 64-bit u-boot HTTP
	riscV32Uefi = 25,           // RISC-V 32-bit UEFI
	riscV32UefiHttp = 26,       // RISC-V 32-bit UEFI HTTP
	riscV64Uefi = 27,           // RISC-V 64-bit UEFI
	riscV64UefiHttp = 28,       // RISC-V 64-bit UEFI HTTP
	riscV128Uefi = 29,          // RISC-V 128-bit UEFI
	riscV128UefiHttp = 30,      // RISC-V 128-bit UEFI HTTP
	s390Basic = 31,             // s390 Basic
	s390Extended = 32,          // s390 Extended
	mips32Uefi = 33,            // MIPS 32-bit UEFI
	mips64Uefi = 34,            // MIPS 64-bit UEFI
	sunwayUefi = 35,            // Sunway 32-bit UEFI
	sunway64Uefi = 36,          // Sunway 64-bit UEFI
	loongArch32Uefi = 37,       // LoongArch 32-bit UEFI
	loongArch32UefiHttp = 38,   // LoongArch 32-bit UEFI HTTP
	loongArch64Uefi = 39,       // LoongArch 64-bit UEFI
	loongArch64UefiHttp = 40,   // LoongArch 64-bit UEFI HTTP
	armRpiboot = 41,            // ARM rpiboot
}

/// Format processor architecture type as human-readable string
string formatProcessorArchitecture(ushort value)
{
	// Check if it's a known enum value
	foreach (member; EnumMembers!ProcessorArchitecture)
	{
		if (value == member)
			return member.to!string;
	}

	// Unknown value - return numeric representation
	return value.to!string;
}

/// Parse processor architecture type from string
ushort parseProcessorArchitecture(string s)
{
	s = s.strip();

	// Try to parse as enum member name
	foreach (member; EnumMembers!ProcessorArchitecture)
	{
		if (s.toLower() == member.to!string.toLower())
			return member;
	}

	// Try to parse as numeric value
	return s.to!ushort;
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
		  0 : DHCPOptionSpec("Pad Option", OptionFormat.special),
		  1 : DHCPOptionSpec("Subnet Mask", OptionFormat.ip),
		  2 : DHCPOptionSpec("Time Offset", OptionFormat.duration),
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
		 51 : DHCPOptionSpec("IP Address Lease Time", OptionFormat.duration),
		 52 : DHCPOptionSpec("Option Overload", OptionFormat.clientIdentifier),
		 53 : DHCPOptionSpec("DHCP Message Type", OptionFormat.dhcpMessageType),
		 54 : DHCPOptionSpec("Server Identifier", OptionFormat.ip),
		 55 : DHCPOptionSpec("Parameter Request List", OptionFormat.dhcpOptionType),
		 56 : DHCPOptionSpec("Message", OptionFormat.str),
		 57 : DHCPOptionSpec("Maximum DHCP Message Size", OptionFormat.u16),
		 58 : DHCPOptionSpec("Renewal (T1) Time Value", OptionFormat.duration),
		 59 : DHCPOptionSpec("Rebinding (T2) Time Value", OptionFormat.duration),
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
		 // RFC 4702 - The DHCP Client FQDN Option
		 // Format: flags (1 byte) + rcode1 (1 byte, deprecated) + rcode2 (1 byte, deprecated) + domain name (DNS wire format)
		 // Used by clients to communicate their fully qualified domain name to DHCP servers
		 // and to negotiate which party (client or server) should perform DNS updates
		 81 : DHCPOptionSpec("Client FQDN", OptionFormat.clientFQDN),
		 82 : DHCPOptionSpec("Relay Agent Information", OptionFormat.relayAgent),
		 // RFC 4578 / RFC 5970 - Client System Architecture Type
		 // See IANA Processor Architecture Types registry for full list
		 // Common values: 0=x86 BIOS, 6=x86 UEFI, 7=x64 UEFI, 10=ARM32 UEFI, 11=ARM64 UEFI
		 93 : DHCPOptionSpec("Client System Architecture Type", OptionFormat.processorArchitecture),
		 // RFC 5859 - TFTP Server Address Option for DHCPv4
		 // List of IPv4 addresses for TFTP/configuration servers (Cisco VoIP phones, etc.)
		 // Servers should be listed in order of preference
		150 : DHCPOptionSpec("TFTP Server Address", OptionFormat.ips),
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

unittest
{
	import dhcptest.formats;

	// Test Option 93 - Client System Architecture Type (RFC 4578/5970)
	// Displays architecture names instead of numbers for better readability

	assert(dhcpOptions[93].name == "Client System Architecture Type");
	assert(dhcpOptions[93].format == OptionFormat.processorArchitecture);

	// Test parsing by architecture name - x86 BIOS (Type 0)
	auto biosx86 = parseOption("x86BiosInt13h", OptionFormat.processorArchitecture);
	assert(biosx86 == [0x00, 0x00]);
	assert(formatValue(biosx86, OptionFormat.processorArchitecture) == "x86BiosInt13h");

	// Test parsing by numeric value - x86 UEFI (Type 6)
	auto efi32 = parseOption("6", OptionFormat.processorArchitecture);
	assert(efi32 == [0x00, 0x06]);
	assert(formatValue(efi32, OptionFormat.processorArchitecture) == "x86Uefi");

	// Test parsing by name - x64 UEFI (Type 7)
	auto efi64 = parseOption("x64Uefi", OptionFormat.processorArchitecture);
	assert(efi64 == [0x00, 0x07]);
	assert(formatValue(efi64, OptionFormat.processorArchitecture) == "x64Uefi");

	// Test EBC (Type 9)
	auto ebc = parseOption("ebc", OptionFormat.processorArchitecture);
	assert(ebc == [0x00, 0x09]);
	assert(formatValue(ebc, OptionFormat.processorArchitecture) == "ebc");

	// Test ARM64 UEFI (Type 11) - popular for modern ARM systems
	auto arm64 = parseOption("arm64Uefi", OptionFormat.processorArchitecture);
	assert(arm64 == [0x00, 0x0b]);
	assert(formatValue(arm64, OptionFormat.processorArchitecture) == "arm64Uefi");

	// Test RISC-V 64-bit UEFI (Type 27)
	auto riscv64 = parseOption("27", OptionFormat.processorArchitecture);
	assert(riscv64 == [0x00, 0x1b]);
	assert(formatValue(riscv64, OptionFormat.processorArchitecture) == "riscV64Uefi");

	// Test unknown architecture (e.g., 255) - should return numeric string
	auto unknown = parseOption("255", OptionFormat.processorArchitecture);
	assert(unknown == [0x00, 0xFF]);
	assert(formatValue(unknown, OptionFormat.processorArchitecture) == "255");
}

unittest
{
	// Test Option 150 - TFTP Server Address (RFC 5859)
	// Used by Cisco and Polycom VoIP phones

	assert(dhcpOptions[150].name == "TFTP Server Address");
	assert(dhcpOptions[150].format == OptionFormat.ips);

	// Test single TFTP server
	auto single = parseOption("192.168.1.10", OptionFormat.ips);
	assert(single == [192, 168, 1, 10]);
	assert(formatValue(single, OptionFormat.ips) == "[192.168.1.10]");

	// Test multiple TFTP servers (redundancy)
	// Example: Primary and backup TFTP servers for VoIP phones
	auto multi = parseOption("[192.168.1.10, 192.168.1.11]", OptionFormat.ips);
	assert(multi == [192, 168, 1, 10, 192, 168, 1, 11]);
	assert(formatValue(multi, OptionFormat.ips) == "[192.168.1.10, 192.168.1.11]");

	// Test roundtrip
	auto formatted = formatValue(multi, OptionFormat.ips);
	auto reparsed = parseOption(formatted, OptionFormat.ips);
	assert(reparsed == multi);
}

unittest
{
	// Test Option 81 - Client FQDN (RFC 4702)
	// Used by DHCP clients to communicate their fully qualified domain name
	// and negotiate which party should perform DNS updates

	assert(dhcpOptions[81].name == "Client FQDN");
	assert(dhcpOptions[81].format == OptionFormat.clientFQDN);

	// Test basic FQDN with typical flags
	// flags=1 (S bit set, server should update A record)
	// rcode1=0, rcode2=255 (deprecated fields, RFC-recommended values)
	// name="client.example.com"
	// DNS wire format: [0x06 "client" 0x07 "example" 0x03 "com" 0x00]
	auto basic = parseOption("flags=1, rcode1=0, rcode2=255, name=client.example.com", OptionFormat.clientFQDN);
	assert(basic == [0x01, 0x00, 0xFF, 0x06, 'c', 'l', 'i', 'e', 'n', 't', 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00]);
	assert(formatValue(basic, OptionFormat.clientFQDN) == "flags=1, rcode1=0, rcode2=255, name=client.example.com");

	// Test empty domain name (client requesting server-provided name)
	auto empty = parseOption("flags=0, rcode1=0, rcode2=255, name=", OptionFormat.clientFQDN);
	assert(empty == [0x00, 0x00, 0xFF, 0x00]);
	assert(formatValue(empty, OptionFormat.clientFQDN) == "flags=0, rcode1=0, rcode2=255, name=\"\"");

	// Test roundtrip
	auto formatted = formatValue(basic, OptionFormat.clientFQDN);
	auto reparsed = parseOption(formatted, OptionFormat.clientFQDN);
	assert(reparsed == basic);
}
