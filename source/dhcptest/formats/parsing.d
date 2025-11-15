/**
 * Parser implementation for DHCP option values.
 *
 * This module provides a recursive descent parser for converting
 * DSL string representations into binary DHCP option data.
 */
module dhcptest.formats.parsing;

import std.algorithm;
import std.array;
import std.ascii;
import std.conv;
import std.exception : enforce;
import std.format;
import std.range;
import std.string;

import dhcptest.formats.types;
import dhcptest.options : DHCPOptionType, parseDHCPOptionType, dhcpOptions, DHCPOptionSpec;

// Import network byte order functions
version (Windows)
	static if (__VERSION__ >= 2067)
		import core.sys.windows.winsock2 : htons, htonl;
	else
		import std.c.windows.winsock : htons, htonl;
else
version (Posix)
	import core.sys.posix.netdb : htons, htonl;

/// Lexer/parser for DSL syntax
/// Stateful stream consumer - advances position as it parses
struct OptionParser
{
	string input;
	size_t pos;
	bool atTopLevel;

	this(string input, bool atTopLevel = false)
	{
		this.input = input;
		this.pos = 0;
		this.atTopLevel = atTopLevel;
	}

	/// Main entry point: parse a value of the given type, return bytes
	/// Advances stream position
	ubyte[] parseValue(OptionFormat type)
	{
		// Skip leading whitespace (except for fullString which is greedy)
		if (type != OptionFormat.fullString)
			skipWhitespace();

		final switch (type)
		{
			// Special types (not parseable)
			case OptionFormat.unknown:
				throw new Exception("Cannot parse unknown format");
			case OptionFormat.special:
				throw new Exception("Cannot parse special format");

			// Scalar types
			case OptionFormat.str:
			case OptionFormat.fullString:
				return cast(ubyte[])readString(type);

			case OptionFormat.hex:
				auto s = readString(OptionFormat.str);
				return parseHexBytes(s);

			case OptionFormat.ip:
				auto s = readString(OptionFormat.str);
				return parseIPAddress(s);

			case OptionFormat.boolean:
				auto s = readString(OptionFormat.str);
				return [s.to!bool ? 1 : 0];

			case OptionFormat.u8:
				auto s = readString(OptionFormat.str);
				return [s.to!ubyte];

			case OptionFormat.u16:
				auto s = readString(OptionFormat.str);
				return toBytes(s.to!ushort.htons);

			case OptionFormat.u32:
				auto s = readString(OptionFormat.str);
				return toBytes(s.to!uint.htonl);

			case OptionFormat.duration:
				auto s = readString(OptionFormat.str);
				return toBytes(parseTimeValue(s).htonl);

			case OptionFormat.dhcpMessageType:
				auto s = readString(OptionFormat.str);
				return [s.to!DHCPMessageType];

			case OptionFormat.dhcpOptionType:
				auto s = readString(OptionFormat.str);
				return [parseDHCPOptionType(s)];

			case OptionFormat.netbiosNodeType:
				auto s = readString(OptionFormat.str);
				// Parse NetBIOS node type: "B", "P", "M", "H", or combinations like "BP"
				ubyte result = 0;
				foreach (c; s)
				{
					auto idx = NETBIOSNodeTypeChars.indexOf(c);
					enforce(idx >= 0, format("Invalid NetBIOS node type character: '%s'", c));
					result |= (1 << idx);
				}
				return [result];

			case OptionFormat.processorArchitecture:
				auto s = readString(OptionFormat.str);
				// Parse processor architecture type (by name or number)
				ushort value = parseProcessorArchitecture(s);
				// Return as u16 in network byte order (big-endian)
				return [cast(ubyte)(value >> 8), cast(ubyte)(value & 0xFF)];

			case OptionFormat.zeroLength:
				auto s = readString(OptionFormat.str);
				enforce(s == "present", "Zero-length option value must be \"present\"");
				return [];

			// Array types
			case OptionFormat.ips:
				return parseSpaceSeparatedArray(OptionFormat.ip);

			case OptionFormat.u8s:
				return parseSpaceSeparatedArray(OptionFormat.u8);

			case OptionFormat.u16s:
				return parseSpaceSeparatedArray(OptionFormat.u16);

			case OptionFormat.u32s:
				return parseSpaceSeparatedArray(OptionFormat.u32);

			case OptionFormat.durations:
				return parseSpaceSeparatedArray(OptionFormat.duration);

			case OptionFormat.dhcpOptionTypes:
				return parseArray(OptionFormat.dhcpOptionType);

			// Struct types - use fullString at top level to consume entire input
			case OptionFormat.classlessStaticRoute:
				// Support two formats:
				// 1. Arrow format: "192.168.2.0/24 -> 192.168.1.50"
				// 2. Array format: [["192.168.2.0/24", "192.168.1.50"], ...]
				skipWhitespace();
				if (!atEnd && peek() == '[')
				{
					// Array format - array of [subnet, router] pairs
					consume(); // outer '['
					skipWhitespace();

					ubyte[] result;
					bool first = true;
					while (!atEnd && peek() != ']')
					{
						if (!first)
						{
							expect(',');
							skipWhitespace();
						}
						first = false;

						// Parse a single route: ["subnet", "router"]
						expect('[');
						skipWhitespace();
						auto subnet = readString(OptionFormat.str);
						skipWhitespace();
						expect(',');
						skipWhitespace();
						auto router = readString(OptionFormat.str);
						skipWhitespace();
						expect(']');

						// Append this route to result
						result ~= parseClasslessStaticRoute(subnet ~ " -> " ~ router);
						skipWhitespace();
					}
					expect(']'); // outer ']'
					return result;
				}
				else
				{
					// Arrow format (legacy)
					auto s = readString(atTopLevel ? OptionFormat.fullString : OptionFormat.str);
					return parseClasslessStaticRoute(s);
				}

			case OptionFormat.clientIdentifier:
				return parseClientIdentifier();

			case OptionFormat.option:
				// Parse DHCP option specification: name[format]=value
				// Encoding: [optionType][value...]
				auto parsed = parseField((name) {
					// Get default format for this option
					auto opt = parseDHCPOptionType(name);
					return dhcpOptions.get(opt, DHCPOptionSpec.init).format;
				});
				string fieldName = parsed[0];
				// OptionFormat fieldFormat = parsed[1];  // Format already applied during parsing
				ubyte[] value = parsed[2];

				// Convert option name to type and encode
				auto opt = parseDHCPOptionType(fieldName);
				ubyte[] result;
				result ~= cast(ubyte)opt;
				result ~= value;
				return result;

			case OptionFormat.relayAgent:
				return parseTLVList!RelayAgentSuboption();

			case OptionFormat.vendorSpecificInformation:
				return parseTLVList!VendorSpecificSuboption();
		}
	}

	/// Parse an array: [v1, v2, ...] or v1, v2, ... (top-level only)
	/// Recursively calls parseValue for each element
	/// At top level, brackets are optional (like fullString)
	ubyte[] parseArray(OptionFormat elementType)
	{
		bool hasBracket = false;

		skipWhitespace();

		// At top level, brackets are optional
		if (atTopLevel)
		{
			if (!atEnd && peek() == '[')
			{
				hasBracket = true;
				consume();
			}
		}
		else
		{
			// Embedded arrays must have brackets
			expect('[');
			hasBracket = true;
		}

		skipWhitespace();

		ubyte[] result;

		// Empty array - only possible with brackets
		if (hasBracket && tryConsume(']'))
			return result;

		// When parsing array elements, we're no longer at top level
		// (to avoid greedy consumption of entire input by readPhrase)
		auto savedTopLevel = atTopLevel;
		atTopLevel = false;
		scope(exit) atTopLevel = savedTopLevel;

		while (true)
		{
			// Parse element (now with atTopLevel=false)
			result ~= parseValue(elementType);

			// Optional comment after element
			if (peekComment())
				skipComment();

			skipWhitespace();

			// Check for end based on whether we have bracket
			if (hasBracket)
			{
				// With bracket: check for ']' or ','
				if (tryConsume(']'))
					break;
				expect(',');
				skipWhitespace();
				// Check for trailing comma
				if (tryConsume(']'))
					break;
			}
			else
			{
				// Without bracket (top level only): check for end of input or ','
				if (atEnd)
					break;
				expect(',');
				skipWhitespace();
				// After comma, if we hit end, that's OK (trailing comma)
				if (atEnd)
					break;
			}
		}

		return result;
	}

	/// Parse a space-separated array where whitespace acts as a delimiter
	/// Supports: "1 2 3", "1,2,3", "1 2, 3 4", "[1, 2 3]"
	/// Used for types where whitespace is never valid within values (IPs, integers)
	ubyte[] parseSpaceSeparatedArray(OptionFormat elementType)
	{
		bool hasBracket = false;

		skipWhitespace();

		// At top level, brackets are optional
		if (atTopLevel)
		{
			if (!atEnd && peek() == '[')
			{
				hasBracket = true;
				consume();
			}
		}
		else
		{
			// Embedded arrays must have brackets
			expect('[');
			hasBracket = true;
		}

		skipWhitespace();

		ubyte[] result;

		// Empty array - only possible with brackets
		if (hasBracket && tryConsume(']'))
			return result;

		// Parse elements with space-separated semantics
		auto savedTopLevel = atTopLevel;
		atTopLevel = false;
		scope(exit) atTopLevel = savedTopLevel;

		while (true)
		{
			// Parse element using word parser (stops at whitespace)
			auto str = readWord();
			if (str.length == 0)
				break;

			// Parse the string value according to element type
			auto p = OptionParser(str, false);
			result ~= p.parseValue(elementType);

			// Optional comment after element
			if (peekComment())
				skipComment();

			// Skip whitespace and optional commas
			skipWhitespace();
			if (!atEnd && peek() == ',')
			{
				consume();
				skipWhitespace();
			}

			// Check for end
			if (hasBracket)
			{
				if (!atEnd && peek() == ']')
				{
					consume();
					break;
				}
			}
			else
			{
				if (atEnd)
					break;
			}
		}

		return result;
	}

	/// Parse a TLV (Type-Length-Value) list
	/// Format: type="value", type2="value2", raw="unparseable"
	/// EnumType is the enum for suboption types (or ubyte for no enum)
	ubyte[] parseTLVList(EnumType)()
	{
		return parseStruct(
			// getDefaultFieldFormat: all TLV values are strings
			(string name) => OptionFormat.str,
			// finalize: encode fields as TLV bytes
			(ubyte[][string] fields) {
				ubyte[] result;

				foreach (name, valueBytes; fields)
				{
					auto valueStr = cast(string)valueBytes;

					// Check if this is the "raw" pseudo-suboption
					if (name == "raw")
					{
						// Raw bytes - no type/length prefix
						result ~= cast(ubyte[])valueStr;
					}
					else
					{
						// Regular suboption - encode as TLV
						ubyte typeValue;

						// Try to parse typeName as numeric first, then as enum name
						static if (is(EnumType == ubyte))
						{
							// For ubyte alias, just parse as number
							typeValue = name.to!ubyte;
						}
						else
						{
							// For enum types, try enum name first, then numeric
							try
							{
								typeValue = cast(ubyte)name.to!EnumType;
							}
							catch (Exception)
							{
								// Try as numeric
								typeValue = name.to!ubyte;
							}
						}

						auto value = cast(ubyte[])valueStr;
						enforce(value.length <= 255, "Suboption value too long (max 255 bytes)");

						result ~= typeValue;
						result ~= cast(ubyte)value.length;
						result ~= value;
					}
				}

				return result;
			}
		);
	}

	/// Parse client identifier struct
	/// Format: type=N, clientIdentifier=hex
	ubyte[] parseClientIdentifier()
	{
		return parseStruct(
			// getDefaultFieldFormat: type is u8, clientIdentifier is hex
			(string name) {
				if (name == "type") return OptionFormat.u8;
				if (name == "clientIdentifier") return OptionFormat.hex;
				return OptionFormat.hex;
			},
			// finalize: encode as type byte followed by identifier bytes
			(ubyte[][string] fields) {
				enforce("type" in fields, "Client identifier must have 'type' field");
				enforce("clientIdentifier" in fields, "Client identifier must have 'clientIdentifier' field");

				ubyte[] result = fields["type"];
				result ~= fields["clientIdentifier"];
				return result;
			}
		);
	}

	/// Parse field name with optional format override: name or name[format]
	/// JSON mode: "name" or "name[format]" (quoted, no separate format override)
	/// Returns: tuple of (field name, format if specified, null otherwise)
	auto parseFieldSpec()
	{
		import std.typecons : tuple, Nullable;

		string name;
		bool isQuoted = false;

		// Parse field name - either quoted or unquoted
		if (!atEnd && peek() == '"')
		{
			// Quoted field name (JSON style) - includes everything in quotes
			name = readQuoted();
			isQuoted = true;
		}
		else
		{
			// Unquoted field name (DSL style) - stops at special chars
			auto nameStart = pos;
			while (!atEnd && !isSpecialChar(peek()) && !isWhitespace(peek()))
				consume();
			name = input[nameStart .. pos];
			enforce(name.length > 0, "Expected field name");
		}

		skipWhitespace();

		// Optional format override: field[format]
		// Only available for unquoted field names
		Nullable!OptionFormat formatOverride;
		if (!isQuoted && tryConsume('['))
		{
			auto fmtStart = pos;
			while (!atEnd && peek() != ']')
				consume();
			auto formatName = input[fmtStart .. pos];
			expect(']');
			skipWhitespace();

			// Parse format name to OptionFormat enum
			formatOverride = formatName.to!OptionFormat;
		}

		return tuple(name, formatOverride);
	}

	/// Parse a single field with format: name[format]=value
	/// Returns: tuple of (field name, format used, value bytes)
	auto parseField(scope OptionFormat delegate(string name) getDefaultFieldFormat)
	{
		import std.typecons : tuple;

		auto spec = parseFieldSpec();
		string name = spec[0];
		auto formatOverride = spec[1];

		// Use format override if specified, otherwise use default
		OptionFormat fieldFormat = formatOverride.isNull
			? getDefaultFieldFormat(name)
			: formatOverride.get;

		// Accept both = (DSL) and : (JSON) as field separators
		if (!tryConsume('=') && !tryConsume(':'))
			throw new Exception(format("Expected '=' or ':' at position %d", pos));
		skipWhitespace();

		// Parse value according to field format
		ubyte[] value = parseValue(fieldFormat);

		return tuple(name, fieldFormat, value);
	}

	/// Parse a struct/map-like value with field=value pairs
	/// Supports: [field=value], {field:value}, or top-level field=value
	/// getDefaultFieldFormat: determines the format for each field by name
	/// finalize: converts the parsed field map to final bytes
	ubyte[] parseStruct(
		scope OptionFormat delegate(string name) getDefaultFieldFormat,
		scope ubyte[] delegate(ubyte[][string] fields) finalize)
	{
		char delimiter = '\0';  // '\0' = none, '[' = bracket, '{' = brace
		skipWhitespace();

		// Delimiters optional at top level
		if (atTopLevel)
		{
			if (!atEnd && (peek() == '[' || peek() == '{'))
			{
				delimiter = consume();
			}
		}
		else
		{
			// Embedded structs require delimiters
			if (!atEnd && (peek() == '[' || peek() == '{'))
				delimiter = consume();
			else
				expect('[');  // Default to expecting bracket for error message
		}

		skipWhitespace();

		// Empty struct
		if (delimiter != '\0')
		{
			char closingDelimiter = (delimiter == '[') ? ']' : '}';
			if (tryConsume(closingDelimiter))
				return finalize(null);
		}

		ubyte[][string] fields;

		auto savedTopLevel = atTopLevel;
		atTopLevel = false;
		scope(exit) atTopLevel = savedTopLevel;

		while (true)
		{
			skipWhitespace();

			// Check for end before trying to parse field name
			if (delimiter != '\0')
			{
				char closingDelimiter = (delimiter == '[') ? ']' : '}';
				if (!atEnd && peek() == closingDelimiter)
					break;
			}
			else if (atEnd)
				break;

			// Parse single field using parseField helper
			auto parsed = parseField(getDefaultFieldFormat);
			string name = parsed[0];
			// OptionFormat fieldFormat = parsed[1];  // Not needed here
			ubyte[] value = parsed[2];

			// Store in fields map
			fields[name] = value;

			// Optional comment
			if (peekComment())
				skipComment();

			skipWhitespace();

			// Check for end or comma
			if (delimiter != '\0')
			{
				char closingDelimiter = (delimiter == '[') ? ']' : '}';
				if (tryConsume(closingDelimiter))
					break;
			}
			else
			{
				// At top level without delimiters, stop at end of input
				if (atEnd)
					break;
			}

			// Expect comma between fields
			if (!tryConsume(','))
			{
				if (delimiter != '\0')
					expect(',');  // With delimiters, comma is required
				else
					break;  // At top level, comma is optional
			}

			skipWhitespace();

			// Check for trailing comma
			if (delimiter != '\0')
			{
				char closingDelimiter = (delimiter == '[') ? ']' : '}';
				if (tryConsume(closingDelimiter))
					break;
			}
		}

		return finalize(fields);
	}

	// ========================================================================
	// Low-level parsing primitives
	// ========================================================================

	/// Check if we're at end of input
	bool atEnd() const
	{
		return pos >= input.length;
	}

	/// Peek at current character without consuming
	char peek() const
	{
		enforce(!atEnd, "Unexpected end of input");
		return input[pos];
	}

	/// Peek ahead n characters
	char peekAhead(size_t n) const
	{
		enforce(pos + n < input.length, "Unexpected end of input");
		return input[pos + n];
	}

	/// Check if character is available at offset
	bool hasChar(size_t offset = 0) const
	{
		return pos + offset < input.length;
	}

	/// Consume and return current character
	char consume()
	{
		enforce(!atEnd, "Unexpected end of input");
		return input[pos++];
	}

	/// Consume specific character or throw
	void expect(char ch)
	{
		auto got = consume();
		enforce(got == ch, format("Expected '%s' but got '%s' at position %d", ch, got, pos - 1));
	}

	/// Try to consume specific character, return success
	bool tryConsume(char ch)
	{
		if (!atEnd && peek() == ch)
		{
			consume();
			return true;
		}
		return false;
	}

	/// Skip whitespace (spaces, tabs, newlines, carriage returns)
	void skipWhitespace()
	{
		while (!atEnd && isWhitespace(peek()))
			consume();
	}

	/// Check if a comment follows (whitespace + '(')
	bool peekComment()
	{
		size_t savedPos = pos;
		scope(exit) pos = savedPos;

		// Must have at least one whitespace before '('
		if (atEnd || !isWhitespace(peek()))
			return false;

		// Skip whitespace
		while (!atEnd && isWhitespace(peek()))
			consume();

		// Check for '('
		return !atEnd && peek() == '(';
	}

	/// Parse and discard a comment: whitespace followed by (...)
	void skipComment()
	{
		// Skip required whitespace
		enforce(!atEnd && isWhitespace(peek()), "Comment must be preceded by whitespace");
		skipWhitespace();

		expect('(');

		// Skip comment content
		while (!atEnd && peek() != ')')
		{
			if (peek() == '\\' && hasChar(1) && peekAhead(1) == ')')
			{
				consume(); // consume backslash
				consume(); // consume ')'
			}
			else
			{
				consume();
			}
		}

		expect(')');
	}

	/// Check if character is whitespace
	private static bool isWhitespace(char ch)
	{
		return ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r';
	}

	/// Check if character is a special character (needs escaping in unquoted strings)
	private static bool isSpecialChar(char ch)
	{
		return ch == '=' || ch == ':' || ch == '[' || ch == ']' || ch == '{' || ch == '}' || ch == ',' || ch == '"' || ch == '\\';
	}

	/// Parse an escape sequence, return the unescaped character
	private char parseEscape()
	{
		expect('\\');
		enforce(!atEnd, "Incomplete escape sequence at end of input");
		auto ch = consume();

		// Handle escape sequences
		switch (ch)
		{
			case '\\':
			case '"':
			case '[':
			case ']':
			case '=':
			case ',':
			case '(':
			case ')':
				return ch;
			case '0':
				return '\0';
			case 'n':
				return '\n';
			case 'r':
				return '\r';
			case 't':
				return '\t';
			case 'x':
				// Hex escape: \xHH
				enforce(pos + 1 < input.length, "Incomplete hex escape sequence");
				auto hexDigits = input[pos .. pos + 2];
				pos += 2;
				return cast(char)hexDigits.to!ubyte(16);
			case 'u':
				// Unicode escape: \uXXXX (JSON-style)
				enforce(pos + 3 < input.length, "Incomplete unicode escape sequence");
				auto unicodeDigits = input[pos .. pos + 4];
				pos += 4;
				auto codepoint = unicodeDigits.to!ushort(16);
				// For ASCII range, return as char
				enforce(codepoint <= 0xFF, "Unicode escapes beyond \\u00FF not supported");
				return cast(char)codepoint;
			default:
				throw new Exception(format("Invalid escape sequence '\\%s' at position %d", ch, pos - 1));
		}
	}

	/// Parse a quoted string: "..." with escape sequences
	string readQuoted()
	{
		expect('"');
		auto result = appender!string;

		while (!atEnd && peek() != '"')
		{
			if (peek() == '\\')
				result.put(parseEscape());
			else
				result.put(consume());
		}

		expect('"');
		return result.data;
	}

	/// Parse a phrase (multi-word unquoted value)
	/// Stops at: end of input, delimiters (,]), or comments
	/// Consumes: most characters including whitespace, dots, colons, hyphens
	/// Used for values like "DE AD BE EF" or "Router Option"
	string readPhrase()
	{
		auto result = appender!string;

		while (!atEnd)
		{
			// Check for comment (whitespace followed by '(')
			if (peekComment())
				break;

			// Check for escape sequence first
			if (peek() == '\\')
			{
				result.put(parseEscape());
				continue;
			}

			// At top level, consume everything (already handled escapes and comments)
			if (atTopLevel)
			{
				result.put(consume());
			}
			// In embedded context, only stop at actual delimiters: , and ]
			else
			{
				char ch = peek();
				if (ch == ',' || ch == ']')
					break;
				result.put(consume());
			}
		}

		import std.string : strip;
		return result.data.strip();
	}

	/// Parse a word (single-word unquoted value, stops at whitespace)
	/// Used for space-separated arrays where whitespace is a delimiter
	/// Stops at: end of input, delimiters (,]), whitespace, or comments
	/// Examples: "192.168.1.1", "42", "3600"
	string readWord()
	{
		auto result = appender!string;

		while (!atEnd)
		{
			// Check for comment
			if (peekComment())
				break;

			// Check for escape sequence first
			if (peek() == '\\')
			{
				result.put(parseEscape());
				continue;
			}

			char ch = peek();
			// Stop at whitespace, commas, or closing bracket
			if (isWhitespace(ch) || ch == ',' || ch == ']')
				break;

			result.put(consume());
		}

		import std.string : strip;
		return result.data.strip();
	}

	/// Parse a full string (greedy, only at top level)
	/// Consumes everything until end of input (or whitespace + comment)
	string readFullString()
	{
		enforce(atTopLevel, "full_string format only available at top level");

		auto result = appender!string;

		while (!atEnd)
		{
			// Check for comment
			if (peekComment())
				break;

			result.put(consume());
		}

		return result.data;
	}

	/// Parse a string based on type
	string readString(OptionFormat type)
	{
		final switch (type)
		{
			case OptionFormat.fullString:
				return readFullString();
			case OptionFormat.str:
				// Skip leading whitespace for str format
				skipWhitespace();
				// Check if quoted
				if (!atEnd && peek() == '"')
					return readQuoted();
				else
					return readPhrase();
			case OptionFormat.unknown:
			case OptionFormat.special:
			case OptionFormat.hex:
			case OptionFormat.ip:
			case OptionFormat.boolean:
			case OptionFormat.u8:
			case OptionFormat.u16:
			case OptionFormat.u32:
			case OptionFormat.duration:
			case OptionFormat.dhcpMessageType:
			case OptionFormat.dhcpOptionType:
			case OptionFormat.netbiosNodeType:
			case OptionFormat.processorArchitecture:
			case OptionFormat.zeroLength:
			case OptionFormat.ips:
			case OptionFormat.u8s:
			case OptionFormat.u16s:
			case OptionFormat.u32s:
			case OptionFormat.durations:
			case OptionFormat.dhcpOptionTypes:
			case OptionFormat.relayAgent:
			case OptionFormat.vendorSpecificInformation:
			case OptionFormat.classlessStaticRoute:
			case OptionFormat.clientIdentifier:
			case OptionFormat.option:
				throw new Exception("readString called with non-string type");
		}
	}

	/// Parse hex bytes from string (e.g., "DEADBEEF" -> [0xDE, 0xAD, 0xBE, 0xEF])
	private static ubyte[] parseHexBytes(string s)
	{
		s = s.replace(" ", "").replace(":", "").replace("-", "");
		enforce(s.length % 2 == 0, "Hex string must have even length");

		ubyte[] result;
		for (size_t i = 0; i < s.length; i += 2)
		{
			result ~= s[i .. i + 2].to!ubyte(16);
		}
		return result;
	}

	/// Parse IP address from string (e.g., "192.168.1.1" -> [192, 168, 1, 1])
	private static ubyte[] parseIPAddress(string s)
	{
		// Allow spaces and commas as separators (for backwards compatibility)
		s = s.replace(" ", ".").replace(",", ".");
		auto parts = s.split(".");
		enforce(parts.length == 4, "IP address must have 4 octets");

		ubyte[] result;
		foreach (part; parts)
			result ~= part.to!ubyte;

		return result;
	}

	/// Convert numeric type to bytes (preserving byte order)
	private static ubyte[] toBytes(T)(T value)
	{
		return (cast(ubyte*)&value)[0 .. T.sizeof].dup;
	}
}

// ============================================================================
// Backwards compatibility wrappers for formats.d API
// ============================================================================

/// Parse option value from string (formats.d compatibility wrapper)
/// This is the old API - new code should use OptionParser directly
ubyte[] parseOption(string value, OptionFormat fmt)
{
	auto parser = OptionParser(value, true);  // atTopLevel=true
	auto result = parser.parseValue(fmt);

	// Skip optional trailing comment
	if (parser.peekComment())
		parser.skipComment();

	enforce(parser.pos == parser.input.length,
		format("Unexpected trailing input at position %d: '%s'", parser.pos, parser.input[parser.pos..$]));
	return result;
}
