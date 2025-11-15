/**
 * Unit tests for the formats package.
 *
 * This module contains all unit tests for parsing and formatting
 * DHCP option values.
 */
module dhcptest.formats.tests;

import std.algorithm;
import std.conv;
import std.exception;
import std.format;

import dhcptest.formats.types;
import dhcptest.formats.parsing;
import dhcptest.formats.formatting;

// ============================================================================
// Unit Tests
// ============================================================================

unittest
{
	// Test u8 parsing
	{
		auto p = OptionParser("42");
		assert(p.parseValue(OptionFormat.u8) == [42]);
	}

	// Test u8 array parsing (with brackets)
	{
		auto p = OptionParser("[1, 2, 3]");
		assert(p.parseValue(OptionFormat.u8s) == [1, 2, 3]);
	}

	// Test u8 array parsing (without brackets, top-level)
	{
		auto p = OptionParser("1, 2, 3", true); // atTopLevel = true
		assert(p.parseValue(OptionFormat.u8s) == [1, 2, 3]);
	}

	// Test u8 array parsing (no spaces)
	{
		auto p = OptionParser("1,2,3", true); // atTopLevel = true
		assert(p.parseValue(OptionFormat.u8s) == [1, 2, 3]);
	}

	// Test IP parsing
	{
		auto p = OptionParser("192.168.1.1");
		assert(p.parseValue(OptionFormat.ip) == [192, 168, 1, 1]);
	}

	// Test IP array parsing (with brackets)
	{
		auto p = OptionParser("[192.168.1.1, 10.0.0.1]");
		auto result = p.parseValue(OptionFormat.ips);
		assert(result == [192, 168, 1, 1, 10, 0, 0, 1]);
	}

	// Test IP array parsing (without brackets, top-level)
	{
		auto p = OptionParser("192.168.1.1, 10.0.0.1", true); // atTopLevel = true
		auto result = p.parseValue(OptionFormat.ips);
		assert(result == [192, 168, 1, 1, 10, 0, 0, 1]);
	}

	// Test hex parsing
	{
		auto p = OptionParser("DEADBEEF");
		assert(p.parseValue(OptionFormat.hex) == [0xDE, 0xAD, 0xBE, 0xEF]);
	}

	// Test boolean parsing
	{
		auto p = OptionParser("true");
		assert(p.parseValue(OptionFormat.boolean) == [1]);
	}

	// Test zero-length parsing
	{
		auto p = OptionParser("present");
		assert(p.parseValue(OptionFormat.zeroLength) == []);
	}
}

unittest
{
	// Test formatting
	{
		assert(formatValue([42], OptionFormat.u8) == "42");
		assert(formatValue([1, 2, 3], OptionFormat.u8s) == "[1, 2, 3]");
		assert(formatValue([192, 168, 1, 1], OptionFormat.ip) == "192.168.1.1");
		assert(formatValue([192, 168, 1, 1, 10, 0, 0, 1], OptionFormat.ips) == "[192.168.1.1, 10.0.0.1]");
		// Hex now uses maybeAscii format with spaces
		assert(formatValue([0xDE, 0xAD, 0xBE, 0xEF], OptionFormat.hex) == "DE AD BE EF");
		// Hex with ASCII shows ASCII in comment
		assert(formatValue(cast(ubyte[])"test", OptionFormat.hex) == "74 65 73 74 (test)");
		assert(formatValue([1], OptionFormat.boolean) == "true");
		assert(formatValue([0], OptionFormat.boolean) == "false");
		assert(formatValue([], OptionFormat.zeroLength) == "present");
	}

	// Test with comments
	{
		assert(formatValue([42], OptionFormat.u8, "the answer") == "42 (the answer)");
	}
}

unittest
{
	// Test round-trip
	void testRoundTrip(string input, OptionFormat type, ubyte[] expected, bool topLevel = true)
	{
		auto p = OptionParser(input, topLevel);
		auto parsed = p.parseValue(type);
		assert(parsed == expected, format("Parse failed: %s -> %s (expected %s)", input, parsed, expected));

		auto formatted = formatValue(parsed, type);
		auto p2 = OptionParser(formatted, topLevel);
		auto reparsed = p2.parseValue(type);
		assert(reparsed == expected, format("Round-trip failed: %s -> %s -> %s", input, formatted, reparsed));
	}

	testRoundTrip("42", OptionFormat.u8, [42]);
	testRoundTrip("[1, 2, 3]", OptionFormat.u8s, [1, 2, 3]);
	testRoundTrip("192.168.1.1", OptionFormat.ip, [192, 168, 1, 1]);
	testRoundTrip("DEADBEEF", OptionFormat.hex, [0xDE, 0xAD, 0xBE, 0xEF]);
	testRoundTrip("true", OptionFormat.boolean, [1]);
	testRoundTrip("present", OptionFormat.zeroLength, []);
}

unittest
{
	// Test time unit parsing
	{
		auto p1 = OptionParser("3600");
		assert(p1.parseValue(OptionFormat.duration) == [0, 0, 14, 16]);  // 3600 in network byte order

		auto p2 = OptionParser("1h");
		assert(p2.parseValue(OptionFormat.duration) == [0, 0, 14, 16]);  // 1 hour = 3600 seconds

		auto p3 = OptionParser("60m");
		assert(p3.parseValue(OptionFormat.duration) == [0, 0, 14, 16]);  // 60 minutes = 3600 seconds

		auto p4 = OptionParser("3600s");
		assert(p4.parseValue(OptionFormat.duration) == [0, 0, 14, 16]);  // 3600 seconds

		auto p5 = OptionParser("1d");
		assert(p5.parseValue(OptionFormat.duration) == [0, 1, 81, 128]);  // 1 day = 86400 seconds
	}
}

unittest
{
	// Test classlessStaticRoute parsing and formatting
	{
		auto p = OptionParser("192.168.2.0/24 -> 192.168.1.50", true);  // atTopLevel = true
		auto parsed = p.parseValue(OptionFormat.classlessStaticRoute);
		assert(parsed == [0x18, 0xc0, 0xa8, 0x02, 0xc0, 0xa8, 0x01, 0x32]);

		auto formatted = formatValue(parsed, OptionFormat.classlessStaticRoute);
		assert(formatted == "192.168.2.0/24 -> 192.168.1.50");
	}
}

unittest
{
	// Test clientIdentifier parsing and formatting
	{
		auto p = OptionParser("type=1, clientIdentifier=AABBCCDDEEFF", true);  // atTopLevel = true
		auto parsed = p.parseValue(OptionFormat.clientIdentifier);
		assert(parsed == [0x01, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);

		auto formatted = formatValue(parsed, OptionFormat.clientIdentifier);
		assert(formatted == "type=1, clientIdentifier=AA BB CC DD EE FF");
	}
}

unittest
{
	// Test empty array handling
	{
		auto p1 = OptionParser("[]");
		assert(p1.parseValue(OptionFormat.ips) == []);
		assert(formatValue([], OptionFormat.ips) == "[]");

		auto p2 = OptionParser("[]");
		assert(p2.parseValue(OptionFormat.u8s) == []);
		assert(formatValue([], OptionFormat.u8s) == "[]");
	}

	// Test empty string
	{
		auto p = OptionParser("\"\"");
		assert(p.parseValue(OptionFormat.str) == []);
		assert(formatValue([], OptionFormat.str) == `""`);
	}

	// Test empty hex formatting
	{
		assert(formatValue([], OptionFormat.hex) == "");
	}
}

unittest
{
	// Test full uint range (was limited to signed int in old parser - TODO line 412)
	{
		auto p = OptionParser("4294967295");  // Max uint: 0xFFFFFFFF
		auto result = p.parseValue(OptionFormat.u32);
		assert(result == [0xFF, 0xFF, 0xFF, 0xFF]);

		// Round-trip
		auto formatted = formatValue(result, OptionFormat.u32);
		auto p2 = OptionParser(formatted);
		assert(p2.parseValue(OptionFormat.u32) == result);
	}
}

unittest
{
	// Test edge case values
	{
		// u8 boundaries
		auto p1 = OptionParser("0");
		assert(p1.parseValue(OptionFormat.u8) == [0]);

		auto p2 = OptionParser("255");
		assert(p2.parseValue(OptionFormat.u8) == [255]);

		// u16 boundaries
		auto p3 = OptionParser("0");
		assert(p3.parseValue(OptionFormat.u16) == [0, 0]);

		auto p4 = OptionParser("65535");
		assert(p4.parseValue(OptionFormat.u16) == [0xFF, 0xFF]);

		// u32 boundaries
		auto p5 = OptionParser("0");
		assert(p5.parseValue(OptionFormat.u32) == [0, 0, 0, 0]);
	}
}

unittest
{
	// Test hex with spaces and colons (from formats.d line 693-695)
	{
		// Now works even without atTopLevel - only stops at delimiters
		auto p1 = OptionParser("DE AD BE EF");
		assert(p1.parseValue(OptionFormat.hex) == [0xDE, 0xAD, 0xBE, 0xEF]);

		auto p2 = OptionParser("DE:AD:BE:EF");
		assert(p2.parseValue(OptionFormat.hex) == [0xDE, 0xAD, 0xBE, 0xEF]);

		auto p3 = OptionParser("de-ad-be-ef");
		assert(p3.parseValue(OptionFormat.hex) == [0xDE, 0xAD, 0xBE, 0xEF]);

		// Verify that values with spaces/separators work in embedded context
		// Example: parsing "Router Option" as dhcpOptionType without needing atTopLevel
		auto p4 = OptionParser("[Router Option, Domain Name Server Option]");
		// This works because readPhrase only stops at ',' and ']', not whitespace
	}
}

unittest
{
	// Test multi-IP round-trip (was TODO line 601-604: comma-space format)
	{
		auto bytes = cast(ubyte[])[192, 168, 1, 1, 10, 0, 0, 1];
		auto formatted = formatValue(bytes, OptionFormat.ips);
		// Formatted as "[192.168.1.1, 10.0.0.1]" (comma-space)

		auto p = OptionParser(formatted);
		auto reparsed = p.parseValue(OptionFormat.ips);
		assert(reparsed == bytes, "Multi-IP round-trip failed");
	}
}

unittest
{
	// Test hex with ASCII round-trip (was TODO line 606-611: unparseable maybeAscii)
	{
		auto bytes = cast(ubyte[])"test";
		auto formatted = formatValue(bytes, OptionFormat.hex);
		// New format: "74 65 73 74 (test)" - hex first, ASCII in comment
		assert(formatted == "74 65 73 74 (test)");

		auto p = OptionParser(formatted); // No longer needs atTopLevel
		auto reparsed = p.parseValue(OptionFormat.hex);
		assert(reparsed == bytes, "Hex with ASCII round-trip failed");
	}
}

unittest
{
	// Test time with duration round-trip (was TODO line 633-637: unparseable duration)
	{
		auto bytes = cast(ubyte[])[0, 0, 14, 16];  // 3600 seconds
		auto formatted = formatValue(bytes, OptionFormat.duration);
		// New format: "3600 (1 hour)" - number first, duration in comment

		auto p = OptionParser(formatted);
		auto reparsed = p.parseValue(OptionFormat.duration);
		assert(reparsed == bytes, "Time with duration round-trip failed");

		// Also test time unit input
		auto p2 = OptionParser("1h");
		assert(p2.parseValue(OptionFormat.duration) == bytes);
	}
}

unittest
{
	// Test trailing comma support (from formats.d line 726)
	{
		auto p = OptionParser("[1, 2, 3,]");
		assert(p.parseValue(OptionFormat.u8s) == [1, 2, 3]);
	}
}

unittest
{
	// Test u16 and u32 arrays (from formats.d lines 444-447)
	{
		auto p1 = OptionParser("[1000, 2000, 3000]");
		assert(p1.parseValue(OptionFormat.u16s) == [0x03, 0xE8, 0x07, 0xD0, 0x0B, 0xB8]);

		auto p2 = OptionParser("[100000, 200000]");
		assert(p2.parseValue(OptionFormat.u32s) == [0x00, 0x01, 0x86, 0xA0, 0x00, 0x03, 0x0D, 0x40]);
	}
}

unittest
{
	// Test enum name parsing
	{
		// dhcpMessageType - enum member names
		auto p1 = OptionParser("discover");
		assert(p1.parseValue(OptionFormat.dhcpMessageType) == [1]);

		auto p2 = OptionParser("offer");
		assert(p2.parseValue(OptionFormat.dhcpMessageType) == [2]);

		// dhcpOptionType - numeric form (names from dhcpOptions table are full like "Router Option")
		auto p3 = OptionParser("3");
		assert(p3.parseValue(OptionFormat.dhcpOptionType) == [3]);

		auto p4 = OptionParser("6");
		assert(p4.parseValue(OptionFormat.dhcpOptionType) == [6]);

		auto p5 = OptionParser("53");
		assert(p5.parseValue(OptionFormat.dhcpOptionType) == [53]);

		// Test full name from dhcpOptions table (now works without atTopLevel)
		auto p6 = OptionParser("Router Option");
		assert(p6.parseValue(OptionFormat.dhcpOptionType) == [3]);
	}
}

unittest
{
	// Test error handling: out of range values
	{
		import std.exception : assertThrown;

		// u8 out of range
		assertThrown(OptionParser("256").parseValue(OptionFormat.u8));
		assertThrown(OptionParser("-1").parseValue(OptionFormat.u8));

		// u16 out of range
		assertThrown(OptionParser("65536").parseValue(OptionFormat.u16));
		assertThrown(OptionParser("-1").parseValue(OptionFormat.u16));

		// u32 out of range
		assertThrown(OptionParser("4294967296").parseValue(OptionFormat.u32));
		assertThrown(OptionParser("-1").parseValue(OptionFormat.u32));
	}
}

unittest
{
	// Test error handling: malformed input
	{
		import std.exception : assertThrown;

		// Malformed IP
		assertThrown(OptionParser("192.168.1").parseValue(OptionFormat.ip));
		assertThrown(OptionParser("192.168.1.256").parseValue(OptionFormat.ip));

		// Malformed hex
		assertThrown(OptionParser("GG").parseValue(OptionFormat.hex));
		assertThrown(OptionParser("XYZ").parseValue(OptionFormat.hex));

		// Malformed boolean
		assertThrown(OptionParser("maybe").parseValue(OptionFormat.boolean));
	}
}

unittest
{
	// Test strings with special characters
	{
		// Quoted string with brackets
		auto p1 = OptionParser(`"[test]"`);
		assert(p1.parseValue(OptionFormat.str) == cast(ubyte[])"[test]");

		// Quoted string with comma
		auto p2 = OptionParser(`"value,with,commas"`);
		assert(p2.parseValue(OptionFormat.str) == cast(ubyte[])"value,with,commas");

		// Quoted string with equals
		auto p3 = OptionParser(`"key=value"`);
		assert(p3.parseValue(OptionFormat.str) == cast(ubyte[])"key=value");

		// Escaped characters in unquoted string
		auto p4 = OptionParser(`value\,with\,escaped`);
		assert(p4.parseValue(OptionFormat.str) == cast(ubyte[])"value,with,escaped");
	}
}

unittest
{
	// Test comments are properly stripped during parsing
	{
		auto p1 = OptionParser("42 (the answer)");
		assert(p1.parseValue(OptionFormat.u8) == [42]);

		auto p2 = OptionParser("192.168.1.1 (gateway)");
		assert(p2.parseValue(OptionFormat.ip) == [192, 168, 1, 1]);

		auto p3 = OptionParser("[1, 2, 3] (test array)");
		assert(p3.parseValue(OptionFormat.u8s) == [1, 2, 3]);
	}
}

unittest
{
	// Test leading whitespace is properly handled (was TODO formats.d:644-648)
	{
		// Single leading space
		auto p1 = OptionParser(" 42");
		assert(p1.parseValue(OptionFormat.u8) == [42]);

		// Multiple leading spaces
		auto p2 = OptionParser("   192.168.1.1");
		assert(p2.parseValue(OptionFormat.ip) == [192, 168, 1, 1]);

		// Leading spaces with tabs
		auto p3 = OptionParser("  \t53");
		assert(p3.parseValue(OptionFormat.dhcpOptionType) == [53]);

		// Leading spaces with comment (like formatDHCPOptionType output)
		auto p4 = OptionParser("  53 (DHCP Message Type)");
		assert(p4.parseValue(OptionFormat.dhcpOptionType) == [53]);

		// Array with leading spaces in elements
		auto p5 = OptionParser("[ 1 ,  2 ,   3 ]");
		assert(p5.parseValue(OptionFormat.u8s) == [1, 2, 3]);
	}

	// Test that fullString format is NOT whitespace-insensitive (greedy mode)
	{
		auto p = OptionParser("  leading spaces", true); // atTopLevel = true
		auto result = cast(string)p.parseValue(OptionFormat.fullString);
		assert(result == "  leading spaces", "fullString should preserve leading whitespace");
	}
}

unittest
{
	// Test space-separated arrays (backwards compatibility with old parser)
	{
		// Space-separated IPs
		auto p1 = OptionParser("192.168.1.1 10.0.0.1", true); // atTopLevel = true
		auto result1 = p1.parseValue(OptionFormat.ips);
		assert(result1 == [192, 168, 1, 1, 10, 0, 0, 1], "Space-separated IPs should work");

		// Space-separated integers
		auto p2 = OptionParser("1 2 3", true);
		auto result2 = p2.parseValue(OptionFormat.u8s);
		assert(result2 == [1, 2, 3], "Space-separated u8s should work");

		// Mixed space and comma separators
		auto p3 = OptionParser("1 2, 3 4", true);
		auto result3 = p3.parseValue(OptionFormat.u8s);
		assert(result3 == [1, 2, 3, 4], "Mixed space and comma separators should work");

		// Comma-separated still works (backwards compatible)
		auto p4 = OptionParser("192.168.1.1,10.0.0.1", true);
		auto result4 = p4.parseValue(OptionFormat.ips);
		assert(result4 == [192, 168, 1, 1, 10, 0, 0, 1], "Comma-separated IPs should still work");

		// With brackets
		auto p5 = OptionParser("[1 2 3]");
		auto result5 = p5.parseValue(OptionFormat.u8s);
		assert(result5 == [1, 2, 3], "Space-separated with brackets should work");

		// u16 and u32 space-separated
		auto p6 = OptionParser("1000 2000 3000", true);
		auto result6 = p6.parseValue(OptionFormat.u16s);
		assert(result6 == [0x03, 0xE8, 0x07, 0xD0, 0x0B, 0xB8], "Space-separated u16s should work");
	}
}

unittest
{
	// Test VLList types: relayAgent and vendorSpecificInformation
	// Comprehensive tests ported from options.d RelayAgentInformation unittest (lines 256-292)
	void testRelayAgent(ubyte[] bytes, string str)
	{
		// Format bytes to string
		auto formatted = formatValue(bytes, OptionFormat.relayAgent);
		assert(formatted == str, format("Format failed: expected %s, got %s", str, formatted));

		// Parse string to bytes
		auto p = OptionParser(str, true);
		auto parsed = p.parseValue(OptionFormat.relayAgent);
		assert(parsed == bytes, format("Parse failed: expected %s, got %s", bytes, parsed));

		// Round-trip: format → parse → should equal original bytes
		auto p2 = OptionParser(formatted, true);
		auto reparsed = p2.parseValue(OptionFormat.relayAgent);
		assert(reparsed == bytes, format("Round-trip failed: %s", bytes));
	}

	// Empty
	testRelayAgent([], ``);

	// Raw suffix - single unparseable byte (raw-suffix feature)
	testRelayAgent([0x00], `raw="\0"`);

	// Single suboption
	testRelayAgent([0x01, 0x03, 'f', 'o', 'o'], `agentCircuitID=foo`);

	// Suboption followed by raw suffix (unparseable trailing byte)
	testRelayAgent([0x01, 0x03, 'f', 'o', 'o', 0x42], `agentCircuitID=foo, raw=B`);

	// Multiple suboptions
	testRelayAgent(
		[0x01, 0x03, 'f', 'o', 'o', 0x02, 0x03, 'b', 'a', 'r'],
		`agentCircuitID=foo, agentRemoteID=bar`
	);

	// Unknown suboption type (numeric)
	testRelayAgent([0x03, 0x03, 'f', 'o', 'o'], `3=foo`);

	// Test from formats.d line 656-657
	testRelayAgent([0x01, 0x04, 't', 'e', 's', 't'], `agentCircuitID=test`);
}

unittest
{
	// Test vendorSpecificInformation (from formats.d lines 659-661)
	void testVendor(ubyte[] bytes, string str)
	{
		// Format bytes to string
		auto formatted = formatValue(bytes, OptionFormat.vendorSpecificInformation);
		assert(formatted == str, format("Format failed: expected %s, got %s", str, formatted));

		// Parse string to bytes
		auto p = OptionParser(str, true);
		auto parsed = p.parseValue(OptionFormat.vendorSpecificInformation);
		assert(parsed == bytes, format("Parse failed: expected %s, got %s", bytes, parsed));

		// Round-trip
		auto p2 = OptionParser(formatted, true);
		auto reparsed = p2.parseValue(OptionFormat.vendorSpecificInformation);
		assert(reparsed == bytes, format("Round-trip failed: %s", bytes));
	}

	// Test from formats.d
	testVendor([0x01, 0x05, 'v', 'a', 'l', 'u', 'e'], `1=value`);

	// Empty
	testVendor([], ``);

	// Raw suffix - printable character
	testVendor([0x42], `raw=B`);

	// Raw suffix - null byte (from options.d test)
	testVendor([0x00], `raw="\0"`);

	// Raw suffix - invalid UTF-8 byte (should be properly escaped)
	testVendor([0xFF], `raw="\xFF"`);
}

unittest
{
	// Test backwards compatibility wrappers
	import std.algorithm : equal;

	// Test parseOption wrapper
	auto bytes1 = parseOption("192.168.1.1", OptionFormat.ip);
	assert(bytes1.equal([192, 168, 1, 1]));

	auto bytes2 = parseOption("foo bar", OptionFormat.str);
	assert(cast(string)bytes2 == "foo bar");

	auto bytes3 = parseOption("1 2 3", OptionFormat.u8s);
	assert(bytes3.equal([1, 2, 3]));

	// Test formatOption wrapper (alias to formatValue)
	alias formatOption = formatValue;
	assert(formatOption([192, 168, 1, 1], OptionFormat.ip) == "192.168.1.1");
	assert(formatOption([1, 2, 3], OptionFormat.u8s) == "[1, 2, 3]");

	// Test formatRawOption (no comment)
	string formatRawOption(in ubyte[] bytes, OptionFormat fmt)
	{
		return formatValue(bytes, fmt, null);
	}
	assert(formatRawOption([42], OptionFormat.u8) == "42");

	// Test deprecated aliases
	auto bytes4 = parseOption("10.0.0.1", OptionFormat.IP);  // Deprecated alias
	assert(bytes4.equal([10, 0, 0, 1]));
}

unittest
{
	// Test format overrides in struct parsing
	import std.algorithm : equal;

	// Test clientIdentifier with format overrides
	{
		auto p = OptionParser("type=1, clientIdentifier[hex]=AABBCCDD", true);
		auto bytes = p.parseClientIdentifier();
		assert(bytes.equal([1, 0xAA, 0xBB, 0xCC, 0xDD]));
	}

	// Test with different override - type as hex
	{
		auto p = OptionParser("type[hex]=01, clientIdentifier=DEADBEEF", true);
		auto bytes = p.parseClientIdentifier();
		assert(bytes.equal([0x01, 0xDE, 0xAD, 0xBE, 0xEF]));
	}

	// Test TLV with format override - parse value as hex instead of string
	{
		auto p = OptionParser("agentCircuitID[hex]=DEADBEEF", true);
		auto bytes = p.parseTLVList!RelayAgentSuboption();
		assert(bytes.equal([0x01, 0x04, 0xDE, 0xAD, 0xBE, 0xEF]));
	}

	// Test multiple fields with different overrides
	{
		auto p = OptionParser("type[u8]=42, clientIdentifier[hex]=CAFEBABE", true);
		auto bytes = p.parseClientIdentifier();
		assert(bytes.equal([42, 0xCA, 0xFE, 0xBA, 0xBE]));
	}

	// Test array format override (arrays require brackets in struct context)
	{
		auto p = OptionParser("agentCircuitID[u8s]=[1, 2, 3], agentRemoteID=foo", true);
		auto bytes = p.parseTLVList!RelayAgentSuboption();
		// agentCircuitID (type=1): length=3, values=[1,2,3]
		// agentRemoteID (type=2): length=3, values="foo"
		assert(bytes.equal([0x01, 0x03, 1, 2, 3, 0x02, 0x03, 'f', 'o', 'o']));
	}

	// Test with brackets (embedded syntax)
	{
		auto p = OptionParser("[type=1, clientIdentifier[hex]=FF]", false);
		auto bytes = p.parseClientIdentifier();
		assert(bytes.equal([1, 0xFF]));
	}

	// Test ip format override (scalar, no brackets needed)
	{
		auto p = OptionParser("agentCircuitID[ip]=192.168.1.1", true);
		auto bytes = p.parseTLVList!RelayAgentSuboption();
		assert(bytes.equal([0x01, 0x04, 192, 168, 1, 1]));
	}

	// Test ips (array) format override (array requires brackets)
	{
		auto p = OptionParser("agentCircuitID[ips]=[192.168.1.1, 10.0.0.1]", true);
		auto bytes = p.parseTLVList!RelayAgentSuboption();
		assert(bytes.equal([0x01, 0x08, 192, 168, 1, 1, 10, 0, 0, 1]));
	}

	// Test boolean override
	{
		auto p = OptionParser("agentCircuitID[boolean]=true", true);
		auto bytes = p.parseTLVList!RelayAgentSuboption();
		assert(bytes.equal([0x01, 0x01, 1]));
	}

	// Test u16 override
	{
		auto p = OptionParser("agentCircuitID[u16]=1000", true);
		auto bytes = p.parseTLVList!RelayAgentSuboption();
		assert(bytes.equal([0x01, 0x02, 0x03, 0xE8]));  // 1000 in network byte order
	}

	// Test u32 override
	{
		auto p = OptionParser("agentCircuitID[u32]=4294967295", true);
		auto bytes = p.parseTLVList!RelayAgentSuboption();
		assert(bytes.equal([0x01, 0x04, 0xFF, 0xFF, 0xFF, 0xFF]));
	}

	// Test duration override
	{
		auto p = OptionParser("agentCircuitID[duration]=1h", true);
		auto bytes = p.parseTLVList!RelayAgentSuboption();
		assert(bytes.equal([0x01, 0x04, 0x00, 0x00, 0x0E, 0x10]));  // 3600 in network byte order
	}
}

// Test parseOption validation - should consume entire input
unittest
{
	import std.exception : assertThrown;

	// Valid - entire input consumed
	assert(parseOption("192.168.1.1", OptionFormat.ip).equal([192, 168, 1, 1]));
	assert(parseOption("42", OptionFormat.u8).equal([42]));

	// Invalid - trailing input after valid value
	// Note: These only fail if the format doesn't consume the entire input
	assertThrown(parseOption("192.168.1.1extra", OptionFormat.ip));  // Invalid IP format
	assertThrown(parseOption("42garbage", OptionFormat.u8));  // Invalid number
	assertThrown(parseOption("true false", OptionFormat.boolean));  // Extra input after boolean
}
