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
import std.datetime;
import std.exception : enforce;
import std.format;
import std.range;
import std.string;

import dhcptest.formats.types;
import dhcptest.options : DHCPOptionType, formatDHCPOptionType, dhcpOptions, DHCPOptionSpec;

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
	Out output;     /// Output sink
	Syntax syntax;  /// Output syntax style (minimal or json)

	/// Format a value as DSL string to the output sink
	void formatValue(const ubyte[] bytes, OptionFormat type)
	{
		final switch (type)
		{
			// Special types (not formattable)
			case OptionFormat.unknown:
				// Format as hex for unknown types
				output.put(maybeAscii(bytes));
				break;
			case OptionFormat.special:
				throw new Exception("Cannot format special format");

			case OptionFormat.str:
			case OptionFormat.fullString:
				formatScalar(cast(string)bytes);
				break;

			case OptionFormat.hex:
				final switch (syntax)
				{
					case Syntax.json:
						// JSON mode: hex values must be quoted strings
						auto hexStr = bytes.map!(b => format("%02X", b)).join(" ");
						formatScalar(hexStr);
						break;
					case Syntax.plain:
						// Plain mode: hex without ASCII decoration (machine-readable)
						output.put(bytes.map!(b => format("%02X", b)).join(" "));
						break;
					case Syntax.verbose:
						// Verbose mode: hex with ASCII decoration
						output.put(maybeAscii(bytes));
						break;
				}
				break;

			case OptionFormat.ip:
				enforce(bytes.length == 4, "IP address must be 4 bytes");
				formatScalar(format("%(%d.%)", bytes));
				break;

			case OptionFormat.boolean:
				enforce(bytes.length == 1, "Boolean must be 1 byte");
				formatScalar(bytes[0] ? "true" : "false");
				break;

			case OptionFormat.u8:
				enforce(bytes.length == 1, "u8 must be 1 byte");
				formatNumber(bytes[0]);
				break;

			case OptionFormat.u16:
				enforce(bytes.length == 2, "u16 must be 2 bytes");
				auto value = ntohs(*cast(ushort*)bytes.ptr);
				formatNumber(value);
				break;

			case OptionFormat.u32:
				enforce(bytes.length == 4, "u32 must be 4 bytes");
				auto value = ntohl(*cast(uint*)bytes.ptr);
				formatNumber(value);
				break;

			case OptionFormat.duration:
				enforce(bytes.length == 4, "time must be 4 bytes");
				auto value = ntohl(*cast(uint*)bytes.ptr);
				final switch (syntax)
				{
					case Syntax.json:
						// JSON mode: output as plain number
						formatNumber(value);
						break;
					case Syntax.plain:
						// Plain mode: just the number, no duration comment
						formatNumber(value);
						break;
					case Syntax.verbose:
						// Verbose mode: number with human-readable duration as comment
						formatNumber(value);
						formatComment(value.seconds.to!string);
						break;
				}
				break;

			case OptionFormat.dhcpMessageType:
				enforce(bytes.length == 1, "dhcpMessageType must be 1 byte");
				formatScalar((cast(DHCPMessageType)bytes[0]).to!string);
				break;

			case OptionFormat.dhcpOptionType:
				enforce(bytes.length == 1, "dhcpOptionType must be 1 byte");
				// Format as number with description as comment
				// In JSON mode: outputs just the number (e.g., 3)
				// In minimal mode: outputs number with description (e.g., 3 (Router Option))
				auto optionType = cast(DHCPOptionType)bytes[0];
				// Get the option name from the table, or use generic name
				auto spec = dhcpOptions.get(optionType, DHCPOptionSpec.init);
				string optionName = spec.name.length > 0 ? spec.name : format("Option %d", bytes[0]);
				formatNumber(bytes[0]);
				formatComment(optionName);
				break;

			case OptionFormat.netbiosNodeType:
				enforce(bytes.length == 1, "netbiosNodeType must be 1 byte");
				// Format as character string (e.g., "B", "BP", "M")
				string result;
				foreach (i; 0 .. NETBIOSNodeTypeChars.length)
					if ((1 << i) & bytes[0])
						result ~= NETBIOSNodeTypeChars[i];
				formatScalar(result);
				break;

			case OptionFormat.zeroLength:
				enforce(bytes.length == 0, "Zero-length must be empty");
				formatScalar("present");
				break;

			case OptionFormat.ips:
				formatArray(bytes, OptionFormat.ip, 4);
				break;

			case OptionFormat.u8s:
				formatArray(bytes, OptionFormat.u8, 1);
				break;

			case OptionFormat.u16s:
				formatArray(bytes, OptionFormat.u16, 2);
				break;

			case OptionFormat.u32s:
				formatArray(bytes, OptionFormat.u32, 4);
				break;

			case OptionFormat.durations:
				formatArray(bytes, OptionFormat.duration, 4);
				break;

			case OptionFormat.dhcpOptionTypes:
				formatArray(bytes, OptionFormat.dhcpOptionType, 1);
				break;

			case OptionFormat.classlessStaticRoute:
				auto routes = formatClasslessStaticRoute(bytes);
				final switch (syntax)
				{
					case Syntax.json:
						// JSON mode: format as array of [subnet, router] pairs
						output.put('[');
						foreach (i, route; routes)
						{
							if (i > 0)
								output.put(", ");
							// Split "subnet/mask -> router" into two parts
							auto parts = route.split(" -> ");
							enforce(parts.length == 2, "Invalid route format");
							output.put('[');
							formatScalar(parts[0]);
							output.put(", ");
							formatScalar(parts[1]);
							output.put(']');
						}
						output.put(']');
						break;
					case Syntax.plain:
						// Plain mode: arrow format like verbose (machine-readable)
						output.put(routes.join(", "));
						break;
					case Syntax.verbose:
						// Verbose mode: use arrow format "subnet/mask -> router, ..."
						output.put(routes.join(", "));
						break;
				}
				break;

			case OptionFormat.clientIdentifier:
				// Format as "type=N, clientIdentifier=hex"
				formatClientIdentifier(bytes);
				break;

			case OptionFormat.relayAgent:
				formatTLVList!RelayAgentSuboption(bytes);
				break;

			case OptionFormat.vendorSpecificInformation:
				formatTLVList!VendorSpecificSuboption(bytes);
				break;

			case OptionFormat.option:
				// Decode: [optionType][value...]
				enforce(bytes.length >= 1, "Option must have at least 1 byte (type)");
				auto opt = cast(DHCPOptionType)bytes[0];
				auto valueBytes = bytes[1 .. $];

				// Get default format for this option
				auto defaultFmt = dhcpOptions.get(opt, DHCPOptionSpec.init).format;

				// Format as field: optionName=value
				formatField(formatDHCPOptionType(opt), valueBytes, defaultFmt);

				break;
		}
	}

	/// Format a field as name=value or name[format]=value (minimal)
	/// or "name": value or "name[format]": value (JSON)
	/// If formatOverride differs from defaultFormat, include the format in brackets
	private void formatField(
		string name,
		const(ubyte)[] value,
		OptionFormat formatUsed,
		OptionFormat defaultFormat = OptionFormat.unknown)
	{
		// Format field name
		final switch (syntax)
		{
			case Syntax.json:
				// JSON mode: quoted field name
				output.put('"');
				output.put(name);
				// Show format override in the quoted name
				if (defaultFormat != OptionFormat.unknown && formatUsed != defaultFormat)
				{
					output.put('[');
					output.put(formatUsed.to!string);
					output.put(']');
				}
				output.put('"');
				output.put(':');
				output.put(' ');
				break;
			case Syntax.plain:
				// Plain mode: unquoted like verbose
				output.put(name);
				if (defaultFormat != OptionFormat.unknown && formatUsed != defaultFormat)
				{
					output.put('[');
					output.put(formatUsed.to!string);
					output.put(']');
				}
				output.put('=');
				break;
			case Syntax.verbose:
				// Verbose mode: unquoted field name
				output.put(name);
				// Show format override after the name
				if (defaultFormat != OptionFormat.unknown && formatUsed != defaultFormat)
				{
					output.put('[');
					output.put(formatUsed.to!string);
					output.put(']');
				}
				output.put('=');
				break;
		}

		formatValue(value, formatUsed);
	}

	/// Format a numeric value (unquoted in both syntaxes)
	private void formatNumber(T : ulong)(T value)
	{
		output.put(value.to!string);
	}

	/// Format a scalar string value for DSL output
	private void formatScalar(string value)
	{
		bool needsQuoting;
		final switch (syntax)
		{
			case Syntax.json:
				// JSON mode: all string values must be quoted
				needsQuoting = true;
				break;
			case Syntax.plain:
				// Plain mode: only quote if necessary (like verbose)
				needsQuoting = value.length == 0;
				if (!needsQuoting)
				{
					foreach (ch; value)
					{
						if (isSpecialChar(ch) || isWhitespace(ch) || ch < 0x20 || ch > 0x7E)
						{
							needsQuoting = true;
							break;
						}
					}
				}
				break;
			case Syntax.verbose:
				// Verbose mode: only quote if necessary
				needsQuoting = value.length == 0;
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
				break;
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
	}

	/// Format an array using callback-based approach (similar to formatStruct)
	/// extractItems: returns all items as ubyte[][]
	/// getItemFormat: returns format for item at given index
	private void formatArray(
		scope ubyte[][] delegate() extractItems,
		scope OptionFormat delegate(size_t index) getItemFormat)
	{
		auto items = extractItems();

		output.put('[');

		bool first = true;
		foreach (i, itemBytes; items)
		{
			if (!first)
				output.put(", ");
			first = false;

			auto itemFormat = getItemFormat(i);
			formatValue(itemBytes, itemFormat);
		}

		output.put(']');
	}

	/// Convenience wrapper for fixed-size element arrays
	private void formatArray(const ubyte[] bytes, OptionFormat elementType, size_t elementSize)
	{
		enforce(bytes.length % elementSize == 0, "Array bytes length not multiple of element size");

		formatArray(
			// extractItems: split bytes into fixed-size chunks
			() {
				ubyte[][] items;
				for (size_t i = 0; i < bytes.length; i += elementSize)
					items ~= bytes[i .. i + elementSize].dup;
				return items;
			},
			// getItemFormat: all items have the same format
			(size_t index) => elementType
		);
	}

	/// Format a comment: (text)
	/// In JSON mode, comments are not output (no-op)
	private void formatComment(string comment)
	{
		final switch (syntax)
		{
			case Syntax.json:
				// Comments are not part of JSON - no-op
				return;
			case Syntax.plain:
				// Plain mode: no comments (machine-readable)
				return;
			case Syntax.verbose:
				// Verbose mode: output comment as (text)
				output.put(' ');
				output.put('(');
				foreach (ch; comment)
				{
					if (ch == ')')
						output.put('\\');
					output.put(ch);
				}
				output.put(')');
				break;
		}
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
				case '\n': output.put(`\n`); break;
				case '\r': output.put(`\r`); break;
				case '\t': output.put(`\t`); break;
				case '\0':
					final switch (syntax)
					{
						case Syntax.json:
							// JSON doesn't support \0, use \u0000
							output.put(`\u0000`);
							break;
						case Syntax.plain:
							output.put(`\0`);
							break;
						case Syntax.verbose:
							output.put(`\0`);
							break;
					}
					break;
				default:
					// For printable ASCII, use as-is
					if (c >= 0x20 && c <= 0x7E)
						output.put(c);
					else
					{
						// For non-printable bytes
						final switch (syntax)
						{
							case Syntax.json:
								// JSON requires Unicode escapes
								formattedWrite(output, `\u%04X`, cast(ubyte)c);
								break;
							case Syntax.verbose:
								// Minimal mode uses hex escapes
							case Syntax.plain:
								// Plain mode uses hex escapes like verbose
								formattedWrite(output, `\x%02X`, cast(ubyte)c);
								break;
						}
					}
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

		// Output opening delimiter
		final switch (syntax)
		{
			case Syntax.json:
				output.put('{');
				if (fields.length > 0)
					output.put(' ');
				break;
			case Syntax.plain:
				// No opening delimiter in plain mode
				break;
			case Syntax.verbose:
				// No opening delimiter in minimal mode
				break;
		}

		bool first = true;
		foreach (name, valueBytes; fields)
		{
			if (!first)
				output.put(", ");
			first = false;

			auto fieldFormat = getFieldFormat(name);
			formatField(name, valueBytes, fieldFormat);
		}

		// Output closing delimiter
		final switch (syntax)
		{
			case Syntax.json:
				if (fields.length > 0)
					output.put(' ');
				output.put('}');
				break;
			case Syntax.plain:
				// No closing delimiter in plain mode
				break;
			case Syntax.verbose:
				// No closing delimiter in minimal mode
				break;
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
string formatValue(const ubyte[] bytes, OptionFormat type, Syntax syntax = Syntax.verbose)
{
	auto buf = appender!string;
	auto formatter = OptionFormatter!(typeof(buf))(buf, syntax);
	formatter.formatValue(bytes, type);
	return buf.data;
}

// ============================================================================
// Backwards compatibility wrappers for formats.d API
// ============================================================================

/// Format option value to string (formats.d compatibility wrapper)
/// This is an alias to formatValue for backwards compatibility
alias formatOption = formatValue;

/// Format option value to string without comment (machine-readable plain format)
string formatRawOption(in ubyte[] bytes, OptionFormat fmt)
{
	return formatValue(bytes, fmt, Syntax.plain);
}
