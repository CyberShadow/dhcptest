/**
 * Formatting implementation for DHCP option values.
 *
 * This module provides functions to convert binary DHCP option data
 * into human-readable DSL string format.
 */
module dhcptest.formats.formatting;

import std.algorithm;
import std.array;
import std.conv;
import std.exception : enforce;
import std.format;
import std.range;
import std.string;

import dhcptest.formats.types;

// Import network byte order functions
version (Windows)
	static if (__VERSION__ >= 2067)
		import core.sys.windows.winsock2 : ntohs, ntohl;
	else
		import std.c.windows.winsock : ntohs, ntohl;
else
version (Posix)
	import core.sys.posix.netdb : ntohs, ntohl;

// ============================================================================
// OptionFormatter - struct-based formatter (similar to OptionParser)
// ============================================================================

/// Formatter for DHCP option values to DSL string format
/// Template parameter Out specifies the output sink type (typically an appender)
struct OptionFormatter(Out)
{
	Out output;  /// Output sink

	/// Format a value as DSL string to the output sink
	void formatValue(const ubyte[] bytes, OptionFormat type, string comment = null)
	{
		final switch (type)
		{
			// Special types (not formattable)
			case OptionFormat.unknown:
				// Format as hex for unknown types
				output.put(maybeAscii(bytes));
				if (comment !is null && comment.length > 0)
					formatComment(comment);
				break;
			case OptionFormat.special:
				throw new Exception("Cannot format special format");

			case OptionFormat.str:
			case OptionFormat.fullString:
				formatScalar(cast(string)bytes, comment);
				break;

			case OptionFormat.hex:
				// Output hex directly without quoting (maybeAscii handles formatting)
				output.put(maybeAscii(bytes));
				if (comment !is null && comment.length > 0)
					formatComment(comment);
				break;

			case OptionFormat.ip:
				enforce(bytes.length == 4, "IP address must be 4 bytes");
				formatScalar(format("%(%d.%)", bytes), comment);
				break;

			case OptionFormat.boolean:
				enforce(bytes.length == 1, "Boolean must be 1 byte");
				formatScalar(bytes[0] ? "true" : "false", comment);
				break;

			case OptionFormat.u8:
				enforce(bytes.length == 1, "u8 must be 1 byte");
				formatScalar(bytes[0].to!string, comment);
				break;

			case OptionFormat.u16:
				enforce(bytes.length == 2, "u16 must be 2 bytes");
				auto value = ntohs(*cast(ushort*)bytes.ptr);
				formatScalar(value.to!string, comment);
				break;

			case OptionFormat.u32:
				enforce(bytes.length == 4, "u32 must be 4 bytes");
				auto value = ntohl(*cast(uint*)bytes.ptr);
				formatScalar(value.to!string, comment);
				break;

			case OptionFormat.duration:
				enforce(bytes.length == 4, "time must be 4 bytes");
				auto value = *cast(uint*)bytes.ptr;  // Keep network byte order for ntime
				// Output time directly without quoting (ntime handles formatting)
				output.put(ntime(value));
				if (comment !is null && comment.length > 0)
					formatComment(comment);
				break;

			case OptionFormat.dhcpMessageType:
				enforce(bytes.length == 1, "dhcpMessageType must be 1 byte");
				formatScalar((cast(DHCPMessageType)bytes[0]).to!string, comment);
				break;

			case OptionFormat.dhcpOptionType:
				enforce(bytes.length == 1, "dhcpOptionType must be 1 byte");
				// Output directly without quoting (formatDHCPOptionType has spaces/parens)
				output.put(formatDHCPOptionType(cast(DHCPOptionType)bytes[0]));
				if (comment !is null && comment.length > 0)
					formatComment(comment);
				break;

			case OptionFormat.netbiosNodeType:
				enforce(bytes.length == 1, "netbiosNodeType must be 1 byte");
				// Format as character string (e.g., "B", "BP", "M")
				string result;
				foreach (i; 0 .. NETBIOSNodeTypeChars.length)
					if ((1 << i) & bytes[0])
						result ~= NETBIOSNodeTypeChars[i];
				formatScalar(result, comment);
				break;

			case OptionFormat.zeroLength:
				enforce(bytes.length == 0, "Zero-length must be empty");
				formatScalar("present", comment);
				break;

			case OptionFormat.ips:
				formatArray(bytes, OptionFormat.ip, 4, comment);
				break;

			case OptionFormat.u8s:
				formatArray(bytes, OptionFormat.u8, 1, comment);
				break;

			case OptionFormat.u16s:
				formatArray(bytes, OptionFormat.u16, 2, comment);
				break;

			case OptionFormat.u32s:
				formatArray(bytes, OptionFormat.u32, 4, comment);
				break;

			case OptionFormat.durations:
				formatArray(bytes, OptionFormat.duration, 4, comment);
				break;

			case OptionFormat.dhcpOptionTypes:
				formatArray(bytes, OptionFormat.dhcpOptionType, 1, comment);
				break;

			case OptionFormat.classlessStaticRoute:
				// Format as route strings, e.g., "192.168.2.0/24 -> 192.168.1.50, ..."
				auto routes = formatClasslessStaticRoute(bytes);
				output.put(routes.join(", "));
				if (comment !is null && comment.length > 0)
					formatComment(comment);
				break;

			case OptionFormat.clientIdentifier:
				// Format as "type=N, clientIdentifier=hex"
				formatClientIdentifier(bytes);
				if (comment !is null && comment.length > 0)
					formatComment(comment);
				break;

			case OptionFormat.relayAgent:
				formatTLVList!RelayAgentSuboption(bytes);
				if (comment !is null && comment.length > 0)
					formatComment(comment);
				break;

			case OptionFormat.vendorSpecificInformation:
				formatTLVList!VendorSpecificSuboption(bytes);
				if (comment !is null && comment.length > 0)
					formatComment(comment);
				break;
		}
	}

	/// Format a field as name=value or name[format]=value
	/// If formatOverride differs from defaultFormat, include the format in brackets
	private void formatField(
		string name,
		const(ubyte)[] value,
		OptionFormat formatUsed,
		OptionFormat defaultFormat = OptionFormat.unknown)
	{
		output.put(name);

		// Show format override if it differs from default
		if (defaultFormat != OptionFormat.unknown && formatUsed != defaultFormat)
		{
			output.put('[');
			output.put(formatUsed.to!string);
			output.put(']');
		}

		output.put('=');
		formatValue(value, formatUsed);
	}

	/// Format a scalar string value for DSL output
	private void formatScalar(string value, string comment = null)
	{
		// Check if value needs quoting
		bool needsQuoting = value.length == 0;

		if (!needsQuoting)
		{
			foreach (ch; value)
			{
				// Need quoting if special char, whitespace, or non-printable
				if (isSpecialChar(ch) || isWhitespace(ch) || ch < 0x20 || ch > 0x7E)
				{
					needsQuoting = true;
					break;
				}
			}
		}

		if (needsQuoting)
		{
			output.put('"');
			formatEscapedString(value);
			output.put('"');
		}
		else
		{
			output.put(value);
		}

		// Add comment if present
		if (comment !is null && comment.length > 0)
			formatComment(comment);
	}

	/// Format an array
	private void formatArray(const ubyte[] bytes, OptionFormat elementType, size_t elementSize, string comment = null)
	{
		enforce(bytes.length % elementSize == 0, "Array bytes length not multiple of element size");

		output.put('[');

		bool first = true;
		for (size_t i = 0; i < bytes.length; i += elementSize)
		{
			if (!first)
				output.put(", ");
			first = false;

			formatValue(bytes[i .. i + elementSize], elementType);
		}

		output.put(']');

		if (comment !is null && comment.length > 0)
			formatComment(comment);
	}

	/// Format a comment: (text)
	private void formatComment(string comment)
	{
		output.put(' ');
		output.put('(');
		foreach (ch; comment)
		{
			if (ch == ')')
				output.put('\\');
			output.put(ch);
		}
		output.put(')');
	}

	/// Format an escaped string to output (for use within quotes)
	private void formatEscapedString(string s)
	{
		foreach (char c; s)
		{
			switch (c)
			{
				case '\\': output.put(`\\`); break;
				case '"':  output.put(`\"`); break;
				case '\0': output.put(`\0`); break;
				case '\n': output.put(`\n`); break;
				case '\r': output.put(`\r`); break;
				case '\t': output.put(`\t`); break;
				default:
					// For printable ASCII, use as-is
					if (c >= 0x20 && c <= 0x7E)
						output.put(c);
					else
						// For non-printable bytes, use hex escape
						formattedWrite(output, `\x%02X`, cast(ubyte)c);
					break;
			}
		}
	}

	/// Helper: check if character is whitespace
	private static bool isWhitespace(char ch)
	{
		return ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r';
	}

	/// Helper: check if character is special
	private static bool isSpecialChar(char ch)
	{
		return ch == '=' || ch == '[' || ch == ']' || ch == ',' || ch == '"' || ch == '\\';
	}

	/// Format a struct/map-like value from bytes to output
	/// extractFields: extracts field name → value bytes map from the input bytes
	/// getFieldFormat: determines the format for each field by name
	private void formatStruct(
		in ubyte[] bytes,
		scope ubyte[][string] delegate(in ubyte[] bytes) extractFields,
		scope OptionFormat delegate(string name) getFieldFormat)
	{
		auto fields = extractFields(bytes);
		bool first = true;

		foreach (name, valueBytes; fields)
		{
			if (!first)
				output.put(", ");
			first = false;

			auto fieldFormat = getFieldFormat(name);
			formatField(name, valueBytes, fieldFormat);
		}
	}

	/// Format a TLV list to DSL string format
	/// Format: type="value", type2="value2", raw="unparseable"
	/// EnumType must have .to!string and be convertible to ubyte
	private void formatTLVList(EnumType)(in ubyte[] bytes)
	{
		formatStruct(
			bytes,
			// extractFields: parse TLV structure into field map
			(in ubyte[] bytes) {
				ubyte[][string] fields;
				size_t i = 0;

				// Parse TLV suboptions
				while (i + 1 < bytes.length)
				{
					ubyte typeValue = bytes[i];
					ubyte length = bytes[i + 1];

					// Check if we have enough bytes for this suboption
					if (i + 2 + length > bytes.length)
						break;  // Incomplete suboption - treat as raw

					i += 2;
					auto value = bytes[i .. i + length];
					i += length;

					// Get type name
					static if (is(EnumType == ubyte))
					{
						// For ubyte, just use the number
						auto typeName = typeValue.to!string;
					}
					else
					{
						// For enums, try to get name
						EnumType type = cast(EnumType)typeValue;
						string typeName = type.to!string;

						// If type.to!string gives "cast(EnumType)N", use numeric form
						if (typeName.startsWith("cast("))
							typeName = typeValue.to!string;
					}

					fields[typeName] = value.dup;
				}

				// Add raw suffix for any remaining bytes
				if (i < bytes.length)
				{
					fields["raw"] = bytes[i .. $].dup;
				}

				return fields;
			},
			// getFieldFormat: all TLV values are strings
			(string name) => OptionFormat.str
		);
	}

	/// Format client identifier from bytes to output
	/// Example: [0x01, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF] -> "type=1, clientIdentifier=AA BB CC DD EE FF"
	private void formatClientIdentifier(in ubyte[] bytes)
	{
		enforce(bytes.length >= 1, "Client identifier must have at least 1 byte (type)");

		formatStruct(
			bytes,
			// extractFields: split into type and clientIdentifier
			(in ubyte[] bytes) {
				ubyte[][string] fields;
				fields["type"] = bytes[0 .. 1].dup;
				if (bytes.length > 1)
					fields["clientIdentifier"] = bytes[1 .. $].dup;
				else
					fields["clientIdentifier"] = [];
				return fields;
			},
			// getFieldFormat: type is u8, clientIdentifier is hex
			(string name) {
				if (name == "type") return OptionFormat.u8;
				if (name == "clientIdentifier") return OptionFormat.hex;
				return OptionFormat.hex;
			}
		);
	}
}

// ============================================================================
// Convenience wrappers
// ============================================================================

/// Format a value as DSL string (convenience wrapper)
string formatValue(const ubyte[] bytes, OptionFormat type, string comment = null)
{
	auto buf = appender!string;
	auto formatter = OptionFormatter!(typeof(buf))(buf);
	formatter.formatValue(bytes, type, comment);
	return buf.data;
}

// ============================================================================
// Backwards compatibility wrappers for formats.d API
// ============================================================================

/// Format option value to string (formats.d compatibility wrapper)
/// This is an alias to formatValue for backwards compatibility
alias formatOption = formatValue;

/// Format option value to string without comment (formats.d compatibility)
string formatRawOption(in ubyte[] bytes, OptionFormat fmt)
{
	return formatValue(bytes, fmt, null);
}
