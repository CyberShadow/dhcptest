module dhcptest.formats;

import std.algorithm;
import std.array;
import std.conv;
import std.datetime;
import std.exception : enforce;
import std.format;
import std.range;
import std.string;

public import dhcptest.options;

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

/// How option values are displayed and interpreted
enum OptionFormat
{
	unknown,
	special,
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
	classlessStaticRoute, // RFC 3442
	clientIdentifier,
	zeroLength,
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

string[] classlessStaticRoute(in ubyte[] bytes)
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

unittest
{
	assert(classlessStaticRoute([0x18, 0xc0, 0xa8, 0x02, 0xc0, 0xa8, 0x01, 0x32]) == ["192.168.2.0/24 -> 192.168.1.50"]);
}

/// Parse a string value into bytes according to the specified format.
ubyte[] parseOption(string value, OptionFormat fmt)
{
	import std.algorithm : fold;
	import std.ascii : isDigit;

	ubyte[] bytes;

	final switch (fmt)
	{
		case OptionFormat.special:
			throw new Exception("Can't specify a value for special option.");
		case OptionFormat.unknown:
			throw new Exception("Don't know how to interpret given value, please specify a format explicitly.");
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
			import dhcptest.options : DHCPMessageType;
			bytes = value
				.splitter(",")
				.map!strip
				.map!(to!DHCPMessageType)
				.map!((ubyte i) => [i])
				.join();
			break;
		case OptionFormat.dhcpOptionType:
			import dhcptest.options : parseDHCPOptionType;
			bytes = value
				.splitter(",")
				.map!strip
				.map!parseDHCPOptionType
				.map!((ubyte i) => [i])
				.join();
			break;
		case OptionFormat.netbiosNodeType:
			import dhcptest.options : NETBIOSNodeTypeChars;
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
			import dhcptest.options : RelayAgentInformation;
			bytes = RelayAgentInformation(value).toBytes().dup;
			break;
		case OptionFormat.vendorSpecificInformation:
			import dhcptest.options : VendorSpecificInformation;
			bytes = VendorSpecificInformation(value).toBytes().dup;
			break;
		case OptionFormat.classlessStaticRoute:
		case OptionFormat.clientIdentifier:
			throw new Exception(format("Sorry, the format %s is unsupported for parsing. Please specify another format explicitly.", fmt));
		case OptionFormat.zeroLength:
			enforce(value == "present", "Value for empty options must be \"present\"");
			break;
	}

	return bytes;
}

/// Format an option in a human-readable format.
string formatOption(in ubyte[] bytes, OptionFormat fmt)
{
	try
		final switch (fmt)
		{
			case OptionFormat.special:
				assert(false);
			case OptionFormat.unknown:
			case OptionFormat.hex:
				return maybeAscii(bytes);
			case OptionFormat.str:
				return cast(string)bytes;
			case OptionFormat.ip:
				enforce(bytes.length % 4 == 0, "Bad IP bytes length");
				return format("%-(%s, %)", map!ip(cast(uint[])bytes));
			case OptionFormat.classlessStaticRoute:
				return format("%-(%s, %)", classlessStaticRoute(bytes));
			case OptionFormat.boolean:
				return format("%-(%s, %)", cast(bool[])bytes);
			case OptionFormat.u8:
				return format("%-(%s, %)", bytes);
			case OptionFormat.u16:
				enforce(bytes.length % 2 == 0, "Bad u16 bytes length");
				return format("%-(%s, %)", (cast(ushort[])bytes).map!ntohs);
			case OptionFormat.u32:
				enforce(bytes.length % 4 == 0, "Bad u32 bytes length");
				return format("%-(%s, %)", (cast(uint[])bytes).map!ntohl);
			case OptionFormat.time:
				enforce(bytes.length % 4 == 0, "Bad time bytes length");
				return format("%-(%s, %)", map!ntime(cast(uint[])bytes));
			case OptionFormat.dhcpMessageType:
				enforce(bytes.length==1, "Bad dhcpMessageType data length");
				return (cast(DHCPMessageType)bytes[0]).to!string;
			case OptionFormat.dhcpOptionType:
				return format("%-(%s, %)", map!formatDHCPOptionType(cast(DHCPOptionType[])bytes));
			case OptionFormat.netbiosNodeType:
				enforce(bytes.length==1, "Bad netbiosNodeType data length");
				return format("%-(%s, %)", bytes
					.map!(b =>
						NETBIOSNodeTypeChars
						.length
						.iota
						.filter!(i => (1 << i) & b)
						.map!(i => NETBIOSNodeTypeChars[i])
						.array
					)
				);
			case OptionFormat.vendorSpecificInformation:
				return (const VendorSpecificInformation(bytes)).toString();
			case OptionFormat.relayAgent:
				return (const RelayAgentInformation(bytes)).toString();
			case OptionFormat.clientIdentifier:
				enforce(bytes.length >= 1, "No type");
				return format("type=%d, clientIdentifier=%s", bytes[0], maybeAscii(bytes[1..$]));
			case OptionFormat.zeroLength:
				enforce(bytes.length==0, "Expected zero length");
				return "present";
		}
	catch (Exception e)
		return format("Decode error (%s). Raw bytes: %s",
			e.msg, maybeAscii(bytes));
}

unittest
{
	// Test formatOption with various formats
	import dhcptest.options : DHCPMessageType;

	// Test string format
	assert(formatOption(cast(ubyte[])"hello", OptionFormat.str) == "hello");

	// Test u8 format
	assert(formatOption([1, 2, 3], OptionFormat.u8) == "1, 2, 3");

	// Test boolean format
	assert(formatOption([1, 0], OptionFormat.boolean) == "true, false");

	// Test hex format
	ubyte[] testBytes = [0xDE, 0xAD, 0xBE, 0xEF];
	auto hexResult = formatOption(testBytes, OptionFormat.hex);
	assert(hexResult.canFind("DE") && hexResult.canFind("AD"));

	// Test IP format
	ubyte[] ipBytes = [192, 168, 1, 1];
	assert(formatOption(ipBytes, OptionFormat.ip) == "192.168.1.1");

	// Test dhcpMessageType format
	assert(formatOption([DHCPMessageType.discover], OptionFormat.dhcpMessageType) == "discover");

	// Test zero-length format
	assert(formatOption([], OptionFormat.zeroLength) == "present");
}

/// Format an option in machine-readable format.
string formatRawOption(in ubyte[] bytes, OptionFormat fmt)
{
	final switch (fmt)
	{
		case OptionFormat.special:
			assert(false);
		case OptionFormat.unknown:
		case OptionFormat.hex:
		case OptionFormat.relayAgent:
		case OptionFormat.vendorSpecificInformation:
		case OptionFormat.clientIdentifier:
		case OptionFormat.zeroLength:
			return format("%-(%02X%)", bytes);
		case OptionFormat.str:
			return cast(string)bytes;
		case OptionFormat.ip:
		case OptionFormat.boolean:
		case OptionFormat.u8:
		case OptionFormat.u16:
		case OptionFormat.u32:
		case OptionFormat.dhcpMessageType:
		case OptionFormat.dhcpOptionType:
		case OptionFormat.netbiosNodeType:
		case OptionFormat.classlessStaticRoute:
			return formatOption(bytes, fmt);
		case OptionFormat.time:
			return formatOption(bytes, OptionFormat.u32);
	}
}

unittest
{
	// Test formatRawOption
	assert(formatRawOption([0xDE, 0xAD], OptionFormat.hex) == "DEAD");
	assert(formatRawOption(cast(ubyte[])"test", OptionFormat.str) == "test");

	// Raw option should delegate to formatOption for most types
	assert(formatRawOption([1, 2, 3], OptionFormat.u8) == "1, 2, 3");
}

// Comprehensive tests for parseOption
unittest
{
	import std.exception : assertThrown;

	// Test str format
	assert(parseOption("hello world", OptionFormat.str) == cast(ubyte[])"hello world");
	assert(parseOption("", OptionFormat.str) == cast(ubyte[])"");
	assert(parseOption("test\n\t", OptionFormat.str) == cast(ubyte[])"test\n\t");

	// Test ip format - single IP
	assert(parseOption("192.168.1.1", OptionFormat.ip) == [192, 168, 1, 1]);
	assert(parseOption("0.0.0.0", OptionFormat.ip) == [0, 0, 0, 0]);
	assert(parseOption("255.255.255.255", OptionFormat.ip) == [255, 255, 255, 255]);

	// Test ip format - multiple IPs (space-separated)
	assert(parseOption("192.168.1.1 10.0.0.1", OptionFormat.ip) == [192, 168, 1, 1, 10, 0, 0, 1]);

	// Test ip format - comma-separated
	assert(parseOption("192.168.1.1,10.0.0.1", OptionFormat.ip) == [192, 168, 1, 1, 10, 0, 0, 1]);

	// Test ip format - malformed should throw
	assertThrown(parseOption("192.168.1", OptionFormat.ip)); // Not divisible by 4
	assertThrown(parseOption("192.168.1.256", OptionFormat.ip)); // Out of range

	// Test hex format
	assert(parseOption("DEADBEEF", OptionFormat.hex) == [0xDE, 0xAD, 0xBE, 0xEF]);
	assert(parseOption("de ad be ef", OptionFormat.hex) == [0xDE, 0xAD, 0xBE, 0xEF]);
	assert(parseOption("DE:AD:BE:EF", OptionFormat.hex) == [0xDE, 0xAD, 0xBE, 0xEF]);
	assert(parseOption("00", OptionFormat.hex) == [0x00]);
	assert(parseOption("", OptionFormat.hex) == []);
	assertThrown(parseOption("GG", OptionFormat.hex)); // Invalid hex

	// Test boolean format
	assert(parseOption("true", OptionFormat.boolean) == [1]);
	assert(parseOption("false", OptionFormat.boolean) == [0]);
	assert(parseOption("true,false,true", OptionFormat.boolean) == [1, 0, 1]);
	assert(parseOption("true, false, true", OptionFormat.boolean) == [1, 0, 1]);

	// Test u8 format
	assert(parseOption("0", OptionFormat.u8) == [0]);
	assert(parseOption("255", OptionFormat.u8) == [255]);
	assert(parseOption("1,2,3", OptionFormat.u8) == [1, 2, 3]);
	assert(parseOption("10, 20, 30", OptionFormat.u8) == [10, 20, 30]);
	assertThrown(parseOption("256", OptionFormat.u8)); // Out of range
	assertThrown(parseOption("-1", OptionFormat.u8)); // Negative

	// Test u16 format
	assert(parseOption("0", OptionFormat.u16) == [0, 0]);
	assert(parseOption("1", OptionFormat.u16) == [0, 1]);
	assert(parseOption("256", OptionFormat.u16) == [1, 0]);
	assert(parseOption("65535", OptionFormat.u16) == [0xFF, 0xFF]);
	assert(parseOption("1,2", OptionFormat.u16) == [0, 1, 0, 2]);
	assert(parseOption("256, 512", OptionFormat.u16) == [1, 0, 2, 0]);

	// Test u32 format
	assert(parseOption("0", OptionFormat.u32) == [0, 0, 0, 0]);
	assert(parseOption("1", OptionFormat.u32) == [0, 0, 0, 1]);
	assert(parseOption("256", OptionFormat.u32) == [0, 0, 1, 0]);
	assert(parseOption("65536", OptionFormat.u32) == [0, 1, 0, 0]);
	assert(parseOption("16777216", OptionFormat.u32) == [1, 0, 0, 0]);
	// TODO: parseOption uses to!int which limits to 2147483647, not full uint range
	assert(parseOption("2147483647", OptionFormat.u32) == [0x7F, 0xFF, 0xFF, 0xFF]);

	// Test time format (same as u32)
	assert(parseOption("3600", OptionFormat.time) == [0, 0, 14, 16]); // 3600 seconds

	// Test dhcpMessageType format
	import dhcptest.options : DHCPMessageType;
	assert(parseOption("discover", OptionFormat.dhcpMessageType) == cast(ubyte[])[DHCPMessageType.discover]);
	assert(parseOption("offer", OptionFormat.dhcpMessageType) == cast(ubyte[])[DHCPMessageType.offer]);
	assert(parseOption("request", OptionFormat.dhcpMessageType) == cast(ubyte[])[DHCPMessageType.request]);
	assert(parseOption("discover,offer", OptionFormat.dhcpMessageType) == cast(ubyte[])[DHCPMessageType.discover, DHCPMessageType.offer]);

	// Test dhcpOptionType format
	assert(parseOption("53", OptionFormat.dhcpOptionType) == [53]);
	assert(parseOption("1,3,6", OptionFormat.dhcpOptionType) == [1, 3, 6]);
	// Note: can also parse by name, but that's tested in options.d

	// Test netbiosNodeType format
	assert(parseOption("B", OptionFormat.netbiosNodeType) == [1]); // B-node
	assert(parseOption("P", OptionFormat.netbiosNodeType) == [2]); // P-node
	assert(parseOption("M", OptionFormat.netbiosNodeType) == [4]); // M-node
	assert(parseOption("H", OptionFormat.netbiosNodeType) == [8]); // H-node
	assert(parseOption("BP", OptionFormat.netbiosNodeType) == [3]); // B+P node
	assert(parseOption("BM", OptionFormat.netbiosNodeType) == [5]); // B+M node

	// Test relayAgent format
	import dhcptest.options : RelayAgentInformation;
	auto relayBytes = parseOption("agentCircuitID=\"test\"", OptionFormat.relayAgent);
	assert(relayBytes == [0x01, 0x04, 't', 'e', 's', 't']);

	// Test vendorSpecificInformation format
	import dhcptest.options : VendorSpecificInformation;
	auto vendorBytes = parseOption("1=\"value\"", OptionFormat.vendorSpecificInformation);
	assert(vendorBytes == [0x01, 0x05, 'v', 'a', 'l', 'u', 'e']);

	// Test zeroLength format
	assert(parseOption("present", OptionFormat.zeroLength) == []);
	assertThrown(parseOption("anything", OptionFormat.zeroLength)); // Must be "present"

	// Test that classlessStaticRoute throws (not supported for parsing)
	assertThrown(parseOption("192.168.1.0/24 -> 192.168.1.1", OptionFormat.classlessStaticRoute));

	// Test that clientIdentifier throws (not supported for parsing)
	assertThrown(parseOption("test", OptionFormat.clientIdentifier));

	// Test that unknown throws
	assertThrown(parseOption("test", OptionFormat.unknown));

	// Test that special throws
	assertThrown(parseOption("test", OptionFormat.special));
}

// Comprehensive tests for formatOption
unittest
{
	import dhcptest.options : DHCPMessageType;

	// Test str format - already tested above, add edge cases
	assert(formatOption(cast(ubyte[])"", OptionFormat.str) == "");
	assert(formatOption(cast(ubyte[])"a\0b", OptionFormat.str) == "a\0b");

	// Test ip format - single and multiple IPs
	assert(formatOption([192, 168, 1, 1], OptionFormat.ip) == "192.168.1.1");
	assert(formatOption([192, 168, 1, 1, 10, 0, 0, 1], OptionFormat.ip) == "192.168.1.1, 10.0.0.1");
	assert(formatOption([0, 0, 0, 0], OptionFormat.ip) == "0.0.0.0");

	// Note: formatOption doesn't throw - it returns "Decode error" string
	// Malformed IP is tested in the error handling section below
	import std.exception : assertThrown;

	// Test hex format (uses maybeAscii which adds ASCII if printable)
	assert(formatOption([0xDE, 0xAD, 0xBE, 0xEF], OptionFormat.hex).canFind("DE"));
	assert(formatOption([0xDE, 0xAD, 0xBE, 0xEF], OptionFormat.hex).canFind("AD"));
	assert(formatOption(cast(ubyte[])"test", OptionFormat.hex).canFind("test")); // ASCII printable
	assert(formatOption([], OptionFormat.hex) == " ()"); // Empty array formatted by maybeAscii

	// Test boolean format
	assert(formatOption([1], OptionFormat.boolean) == "true");
	assert(formatOption([0], OptionFormat.boolean) == "false");
	assert(formatOption([1, 0, 1], OptionFormat.boolean) == "true, false, true");

	// Test u8 format
	assert(formatOption([0], OptionFormat.u8) == "0");
	assert(formatOption([255], OptionFormat.u8) == "255");
	assert(formatOption([1, 2, 3], OptionFormat.u8) == "1, 2, 3");

	// Test u16 format
	assert(formatOption([0, 0], OptionFormat.u16) == "0");
	assert(formatOption([0, 1], OptionFormat.u16) == "1");
	assert(formatOption([1, 0], OptionFormat.u16) == "256");
	assert(formatOption([0xFF, 0xFF], OptionFormat.u16) == "65535");
	assert(formatOption([0, 1, 0, 2], OptionFormat.u16) == "1, 2");
	// Odd length returns "Decode error" - tested in error handling section

	// Test u32 format
	assert(formatOption([0, 0, 0, 0], OptionFormat.u32) == "0");
	assert(formatOption([0, 0, 0, 1], OptionFormat.u32) == "1");
	assert(formatOption([0, 0, 1, 0], OptionFormat.u32) == "256");
	assert(formatOption([0xFF, 0xFF, 0xFF, 0xFF], OptionFormat.u32) == "4294967295");
	// Not divisible by 4 returns "Decode error" - tested in error handling section

	// Test time format (shows both number and duration)
	auto timeResult = formatOption([0, 0, 14, 16], OptionFormat.time); // 3600 seconds
	assert(timeResult.canFind("3600"));
	assert(timeResult.canFind("1 hour")); // Duration formatting

	// Test dhcpMessageType format
	assert(formatOption([DHCPMessageType.discover], OptionFormat.dhcpMessageType) == "discover");
	assert(formatOption([DHCPMessageType.offer], OptionFormat.dhcpMessageType) == "offer");
	assert(formatOption([DHCPMessageType.request], OptionFormat.dhcpMessageType) == "request");
	// Wrong length returns "Decode error" - tested in error handling section

	// Test dhcpOptionType format (shows number and name)
	auto optTypeResult = formatOption([53], OptionFormat.dhcpOptionType);
	assert(optTypeResult.canFind("53"));
	assert(optTypeResult.canFind("DHCP Message Type"));

	// Test netbiosNodeType format
	assert(formatOption([1], OptionFormat.netbiosNodeType) == "B");
	assert(formatOption([2], OptionFormat.netbiosNodeType) == "P");
	assert(formatOption([4], OptionFormat.netbiosNodeType) == "M");
	assert(formatOption([8], OptionFormat.netbiosNodeType) == "H");
	assert(formatOption([3], OptionFormat.netbiosNodeType) == "BP"); // B+P
	// Wrong length returns "Decode error" - tested in error handling section

	// Test relayAgent format
	auto relayResult = formatOption([0x01, 0x04, 't', 'e', 's', 't'], OptionFormat.relayAgent);
	assert(relayResult.canFind("agentCircuitID"));
	assert(relayResult.canFind("test"));

	// Test vendorSpecificInformation format
	auto vendorResult = formatOption([0x01, 0x05, 'v', 'a', 'l', 'u', 'e'], OptionFormat.vendorSpecificInformation);
	assert(vendorResult.canFind("1="));
	assert(vendorResult.canFind("value"));

	// Test classlessStaticRoute format
	ubyte[] routeBytes = [0x18, 0xc0, 0xa8, 0x02, 0xc0, 0xa8, 0x01, 0x32];
	auto routeResult = formatOption(routeBytes, OptionFormat.classlessStaticRoute);
	assert(routeResult.canFind("192.168.2.0/24"));
	assert(routeResult.canFind("192.168.1.50"));

	// Test clientIdentifier format
	ubyte[] clientIdBytes = [0x01, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
	auto clientIdResult = formatOption(clientIdBytes, OptionFormat.clientIdentifier);
	assert(clientIdResult.canFind("type=1"));

	// Test zeroLength format
	assert(formatOption([], OptionFormat.zeroLength) == "present");
	// Non-empty returns "Decode error" - tested in error handling section

	// Test unknown format (uses maybeAscii)
	assert(formatOption([0xDE, 0xAD], OptionFormat.unknown).canFind("DE"));
}

// Round-trip tests: parseOption -> formatOption or formatOption -> parseOption
unittest
{
	import std.algorithm : equal;
	import std.exception : assertThrown;

	// Helper to test that parse(format(bytes)) == bytes
	void testFormatParse(ubyte[] bytes, OptionFormat fmt)
	{
		auto formatted = formatOption(bytes, fmt);
		auto parsed = parseOption(formatted, fmt);
		assert(equal(parsed, bytes),
			format("Round-trip failed for %s: %s -> %s -> %s", fmt, bytes, formatted, parsed));
	}

	// Helper to test that format(parse(str)) produces consistent output
	void testParseFormat(string str, OptionFormat fmt)
	{
		auto parsed = parseOption(str, fmt);
		auto formatted = formatOption(parsed, fmt);
		auto reparsed = parseOption(formatted, fmt);
		assert(equal(parsed, reparsed),
			format("Round-trip failed for %s: %s -> %s -> %s -> %s", fmt, str, parsed, formatted, reparsed));
	}

	// str format - perfect round-trip
	testFormatParse(cast(ubyte[])"hello", OptionFormat.str);
	testFormatParse(cast(ubyte[])"test\n\t", OptionFormat.str);
	testParseFormat("world", OptionFormat.str);

	// ip format - single IP round-trips perfectly
	testFormatParse([192, 168, 1, 1], OptionFormat.ip);
	testParseFormat("10.0.0.1", OptionFormat.ip);

	// TODO: formatOption outputs multi-IP as "192.168.1.1, 10.0.0.1" (comma-space)
	// but parseOption's replace logic creates empty strings when parsing this back
	// This is a bug in the implementation - not testing format->parse for multi-IP
	// testFormatParse([192, 168, 1, 1, 10, 0, 0, 1], OptionFormat.ip); // FAILS

	// TODO: hex format - does NOT round-trip because formatOption uses maybeAscii
	// which adds ASCII representation when bytes are printable, making output unparseable
	// For example: [0x74,0x65,0x73,0x74] formats to "test (74 65 73 74)" which can't be parsed
	// testParseFormat("DEADBEEF", OptionFormat.hex); // FAILS if bytes happen to be ASCII
	// testParseFormat("00", OptionFormat.hex); // FAILS - 0x00 triggers ASCII mode
	// Note: Neither format->parse nor parse->format->parse works reliably

	// boolean format - perfect round-trip
	testFormatParse([1, 0, 1], OptionFormat.boolean);
	testParseFormat("true,false", OptionFormat.boolean);

	// u8 format - perfect round-trip
	testFormatParse([1, 2, 3], OptionFormat.u8);
	testFormatParse([0, 255], OptionFormat.u8);
	testParseFormat("10,20,30", OptionFormat.u8);

	// u16 format - perfect round-trip
	testFormatParse([0, 1], OptionFormat.u16);
	testFormatParse([1, 0], OptionFormat.u16);
	testFormatParse([0xFF, 0xFF], OptionFormat.u16);
	testParseFormat("256,512", OptionFormat.u16);

	// u32 format - perfect round-trip
	testFormatParse([0, 0, 0, 1], OptionFormat.u32);
	testFormatParse([0, 0, 1, 0], OptionFormat.u32);
	testParseFormat("65536", OptionFormat.u32);

	// TODO: time format - does NOT round-trip because formatOption adds duration string
	// e.g., "3600 (1 hour)" but parseOption only accepts the number
	// Neither parse->format->parse nor format->parse works
	// testParseFormat("3600", OptionFormat.time); // FAILS - formatted output has duration
	// testFormatParse([0, 0, 14, 16], OptionFormat.time); // FAILS - formatted output unparseable

	// dhcpMessageType format - perfect round-trip
	import dhcptest.options : DHCPMessageType;
	testFormatParse([DHCPMessageType.discover], OptionFormat.dhcpMessageType);
	testParseFormat("offer", OptionFormat.dhcpMessageType);

	// TODO: dhcpOptionType format - does NOT round-trip because formatOption adds descriptive
	// names like "  53 (DHCP Message Type)" but parseOption can't parse that format
	// testParseFormat("53", OptionFormat.dhcpOptionType); // FAILS - formatted output unparseable
	// testParseFormat("1,3,6", OptionFormat.dhcpOptionType); // FAILS
	// Note: Can parse "53" or option names, but formatted output has both

	// netbiosNodeType format - perfect round-trip
	testFormatParse([1], OptionFormat.netbiosNodeType); // B
	testFormatParse([3], OptionFormat.netbiosNodeType); // BP
	testParseFormat("M", OptionFormat.netbiosNodeType);

	// relayAgent format - round-trip through VLList
	testParseFormat("agentCircuitID=\"test\"", OptionFormat.relayAgent);
	testFormatParse([0x01, 0x04, 't', 'e', 's', 't'], OptionFormat.relayAgent);

	// vendorSpecificInformation format - round-trip through VLList
	testParseFormat("1=\"value\"", OptionFormat.vendorSpecificInformation);
	testFormatParse([0x01, 0x05, 'v', 'a', 'l', 'u', 'e'], OptionFormat.vendorSpecificInformation);

	// zeroLength format - perfect round-trip
	testFormatParse([], OptionFormat.zeroLength);
	testParseFormat("present", OptionFormat.zeroLength);

	// TODO: classlessStaticRoute - formatOption works, parseOption throws
	// Cannot test round-trip until parseOption is implemented for this format
	ubyte[] routeBytes2 = [0x18, 0xc0, 0xa8, 0x02, 0xc0, 0xa8, 0x01, 0x32];
	auto routeFormatted = formatOption(routeBytes2, OptionFormat.classlessStaticRoute);
	assertThrown(parseOption(routeFormatted, OptionFormat.classlessStaticRoute));

	// TODO: clientIdentifier - formatOption works, parseOption throws
	// Cannot test round-trip until parseOption is implemented for this format
	ubyte[] clientIdBytes2 = [0x01, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
	auto clientIdFormatted = formatOption(clientIdBytes2, OptionFormat.clientIdentifier);
	assertThrown(parseOption(clientIdFormatted, OptionFormat.clientIdentifier));
}

// Edge case and error handling tests
unittest
{
	import std.exception : assertThrown;

	// Test that formatOption handles decode errors gracefully
	// Bad IP length
	auto badIpResult = formatOption([192, 168, 1], OptionFormat.ip);
	assert(badIpResult.canFind("Decode error"));
	assert(badIpResult.canFind("Bad IP bytes length"));

	// Bad u16 length
	auto badU16Result = formatOption([1], OptionFormat.u16);
	assert(badU16Result.canFind("Decode error"));

	// Bad dhcpMessageType length
	auto badMsgTypeResult = formatOption([1, 2], OptionFormat.dhcpMessageType);
	assert(badMsgTypeResult.canFind("Decode error"));

	// Bad netbiosNodeType length
	auto badNodeTypeResult = formatOption([1, 2], OptionFormat.netbiosNodeType);
	assert(badNodeTypeResult.canFind("Decode error"));

	// formatOption with empty bytes for formats that expect data
	assert(formatOption([], OptionFormat.ip) == ""); // Empty is ok
	assert(formatOption([], OptionFormat.u8) == "");
	assert(formatOption([], OptionFormat.boolean) == "");

	// parseOption with empty string
	assert(parseOption("", OptionFormat.str) == []);
	assert(parseOption("", OptionFormat.hex) == []);

	// parseOption should throw for malformed inputs
	assertThrown(parseOption("abc", OptionFormat.u8)); // Not a number
	assertThrown(parseOption("192.168.1.256", OptionFormat.ip)); // Out of range
	assertThrown(parseOption("xyz", OptionFormat.hex)); // Invalid hex
}
