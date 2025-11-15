/**
 * Type definitions and utility functions for DHCP option formatting.
 *
 * This module provides type definitions and helper functions used throughout
 * the formats package for parsing and formatting DHCP options.
 */
module dhcptest.formats.types;

import std.algorithm;
import std.array;
import std.ascii : isDigit;
import std.conv;
import std.datetime;
import std.exception : enforce;
import std.format;
import std.range;
import std.string;

// Import DHCP-specific types and helpers
public import dhcptest.options : DHCPMessageType, DHCPOptionType, NETBIOSNodeType, NETBIOSNodeTypeChars, parseDHCPOptionType, formatDHCPOptionType;

// Import network byte order functions
version (Windows)
	static if (__VERSION__ >= 2067)
		import core.sys.windows.winsock2 : ntohl, ntohs, htons, htonl;
	else
		import std.c.windows.winsock : ntohl, ntohs, htons, htonl;
else
version (Posix)
	import core.sys.posix.netdb : ntohl, ntohs, htons, htonl;
else
	static assert(false, "Unsupported platform");

// Utility functions for formatting DHCP packet fields
string ip(uint addr) { return "%(%d.%)".format(cast(ubyte[])((&addr)[0..1])); }

/// Option format types - replaces the old formats.d OptionFormat enum
/// This enum specifies how DHCP option data should be parsed and formatted
enum OptionFormat
{
	// Special types (not directly parseable/formattable)
	unknown,          /// Unknown format (not parseable)
	special,          /// Special option format (not parseable)

	// Scalar types
	str,              /// Regular string (quoted or unquoted with escaping)
	fullString,       /// Greedy raw string (top-level only, no escaping)
	hex,              /// Hex bytes (e.g., "DEADBEEF")
	ip,               /// Single IP address (e.g., "192.168.1.1")
	boolean,          /// Boolean value (true/false)
	u8,               /// Single unsigned 8-bit integer
	u16,              /// Single unsigned 16-bit integer (network byte order)
	u32,              /// Single unsigned 32-bit integer (network byte order)
	duration,         /// Duration value in seconds (u32)
	dhcpMessageType,  /// DHCP message type enum
	dhcpOptionType,   /// DHCP option type
	netbiosNodeType,  /// NetBIOS node type
	zeroLength,       /// Zero-length option (must be "present")

	// Array types (plural naming)
	ips,              /// Array of IP addresses
	u8s,              /// Array of u8 values
	u16s,             /// Array of u16 values
	u32s,             /// Array of u32 values
	durations,        /// Array of duration values
	dhcpOptionTypes,  /// Array of DHCP option types

	// Struct/composite types
	relayAgent,       /// Relay agent information (RFC 3046)
	vendorSpecificInformation, /// Vendor-specific information
	classlessStaticRoute,      /// Classless static routes (RFC 3442)
	clientIdentifier, /// Client identifier (type + data)
	option,           /// DHCP option specification: name[format]=value

	// Backwards compatibility aliases (deprecated)
	IP = ip,          /// Deprecated: use 'ip' instead
	i32 = u32,        /// Deprecated: use 'u32' instead
	time = duration,  /// Deprecated: use 'duration' instead
}

// ============================================================================
// Relay Agent Information and Vendor-Specific Information
// ============================================================================

/// Relay Agent Information suboption types (RFC 3046)
enum RelayAgentSuboption : ubyte
{
	agentCircuitID = 1,
	agentRemoteID = 2,
}

/// Vendor-Specific Information suboption types
/// (No standard suboptions defined - all are vendor-specific)
/// This is just an alias to ubyte since there are no predefined types
alias VendorSpecificSuboption = ubyte;

// ============================================================================
// Helper functions for enhanced display
// ============================================================================

/// Parse time value with optional unit suffix
/// Supports: "3600", "1h", "60m", "3600s"
/// Returns value in seconds
uint parseTimeValue(string s)
{
	s = s.strip();

	// Check for unit suffix
	if (s.length > 1 && !s[$-1].isDigit)
	{
		char unit = s[$-1];
		string numPart = s[0..$-1];
		uint value = numPart.to!uint;

		switch (unit)
		{
			case 's': case 'S':
				return value;  // seconds
			case 'm': case 'M':
				return value * 60;  // minutes to seconds
			case 'h': case 'H':
				return value * 3600;  // hours to seconds
			case 'd': case 'D':
				return value * 86400;  // days to seconds
			default:
				throw new Exception(format("Unknown time unit: '%s'", unit));
		}
	}

	// No unit - interpret as seconds
	return s.to!uint;
}

/// Format time value with duration string
/// Example: "3600 (1 hour)"
string ntime(uint n)
{
	return "%d (%s)".format(n.ntohl, n.ntohl.seconds);
}

/// Format hex bytes, showing ASCII interpretation if all bytes are printable
/// Parseable format: hex first, then ASCII comment
/// Example: "74 65 73 74 (test)"
string maybeAscii(in ubyte[] bytes)
{
	if (bytes.length == 0)
		return "";

	auto s = bytes.map!(b => format("%02X", b)).join(" ");
	if (bytes.all!(b => (b >= 0x20 && b <= 0x7E) || !b))
	{
		auto ascii = (cast(string)bytes).split("\0").join(", ");
		s = "%s (%s)".format(s, ascii);
	}
	return s;
}

/// Format classless static routes from bytes
/// Example: [0x18, 0xc0, 0xa8, 0x02, 0xc0, 0xa8, 0x01, 0x32] -> "192.168.2.0/24 -> 192.168.1.50"
string[] formatClasslessStaticRoute(in ubyte[] bytes)
{
	string[] result;
	size_t i = 0;
	while (i < bytes.length)
	{
		try
		{
			ubyte maskBits = bytes[i++];
			enforce(maskBits <= 32, "Too many bits in mask length");

			ubyte[4] subnet = 0;
			ubyte subnetSignificantBytes = (maskBits + 7) / 8;
			enforce(i + subnetSignificantBytes <= bytes.length, "Not enough bytes for route subnet");
			subnet[0 .. subnetSignificantBytes] = bytes[i .. i + subnetSignificantBytes];
			i += subnetSignificantBytes;

			ubyte[4] routerIP;
			enforce(i + 4 <= bytes.length, "Not enough bytes for router IP");
			routerIP[] = bytes[i .. i + 4];
			i += 4;

			result ~= format!"%(%d.%)/%d -> %(%d.%)"(subnet[], maskBits, routerIP);
		}
		catch (Exception e)
		{
			result ~= format!"(Error: %s) %(%02x %)"(e.msg, bytes);
			break;
		}
	}
	return result;
}

/// Parse classless static route from string
/// Example: "192.168.2.0/24 -> 192.168.1.50" -> [0x18, 0xc0, 0xa8, 0x02, 0xc0, 0xa8, 0x01, 0x32]
ubyte[] parseClasslessStaticRoute(string s)
{
	s = s.strip();

	// Split by "->"
	auto parts = s.split("->");
	enforce(parts.length == 2, "Classless static route must have format: subnet/mask -> router");

	// Parse subnet and mask
	auto subnetPart = parts[0].strip();
	auto subnetParts = subnetPart.split("/");
	enforce(subnetParts.length == 2, "Subnet must have format: IP/mask");

	// Parse subnet IP
	auto subnetIP = subnetParts[0].strip().split(".").map!(to!ubyte).array;
	enforce(subnetIP.length == 4, "Subnet IP must have 4 octets");

	// Parse mask bits
	auto maskBits = subnetParts[1].strip().to!ubyte;
	enforce(maskBits <= 32, "Mask bits must be <= 32");

	// Parse router IP
	auto routerIP = parts[1].strip().split(".").map!(to!ubyte).array;
	enforce(routerIP.length == 4, "Router IP must have 4 octets");

	// Encode as bytes
	ubyte[] result;
	result ~= maskBits;

	// Add significant subnet bytes
	ubyte significantBytes = (maskBits + 7) / 8;
	result ~= subnetIP[0 .. significantBytes];

	// Add router IP
	result ~= routerIP;

	return result;
}
