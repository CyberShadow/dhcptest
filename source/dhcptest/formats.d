module dhcptest.formats;

import std.algorithm;
import std.array;
import std.conv;
import std.datetime;
import std.exception : enforce;
import std.format;
import std.range;
import std.stdio : File;
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

/// Print an option in a human-readable format.
void printOption(File f, in ubyte[] bytes, OptionFormat fmt)
{
	try
		final switch (fmt)
		{
			case OptionFormat.special:
				assert(false);
			case OptionFormat.unknown:
			case OptionFormat.hex:
				f.writeln(maybeAscii(bytes));
				break;
			case OptionFormat.str:
				f.writeln(cast(string)bytes);
				break;
			case OptionFormat.ip:
				enforce(bytes.length % 4 == 0, "Bad IP bytes length");
				f.writefln("%-(%s, %)", map!ip(cast(uint[])bytes));
				break;
			case OptionFormat.classlessStaticRoute:
				f.writefln("%-(%s, %)", classlessStaticRoute(bytes));
				break;
			case OptionFormat.boolean:
				f.writefln("%-(%s, %)", cast(bool[])bytes);
				break;
			case OptionFormat.u8:
				f.writefln("%-(%s, %)", bytes);
				break;
			case OptionFormat.u16:
				enforce(bytes.length % 2 == 0, "Bad u16 bytes length");
				f.writefln("%-(%s, %)", (cast(ushort[])bytes).map!ntohs);
				break;
			case OptionFormat.u32:
				enforce(bytes.length % 4 == 0, "Bad u32 bytes length");
				f.writefln("%-(%s, %)", (cast(uint[])bytes).map!ntohl);
				break;
			case OptionFormat.time:
				enforce(bytes.length % 4 == 0, "Bad time bytes length");
				f.writefln("%-(%s, %)", map!ntime(cast(uint[])bytes));
				break;
			case OptionFormat.dhcpMessageType:
				enforce(bytes.length==1, "Bad dhcpMessageType data length");
				f.writeln(cast(DHCPMessageType)bytes[0]);
				break;
			case OptionFormat.dhcpOptionType:
				f.writefln("%-(%s, %)", map!formatDHCPOptionType(cast(DHCPOptionType[])bytes));
				break;
			case OptionFormat.netbiosNodeType:
				enforce(bytes.length==1, "Bad netbiosNodeType data length");
				f.writefln("%-(%s, %)", bytes
					.map!(b =>
						NETBIOSNodeTypeChars
						.length
						.iota
						.filter!(i => (1 << i) & b)
						.map!(i => NETBIOSNodeTypeChars[i])
						.array
					)
				);
				break;
			case OptionFormat.vendorSpecificInformation:
				f.writeln((const VendorSpecificInformation(bytes)).toString());
				break;
			case OptionFormat.relayAgent:
				f.writeln((const RelayAgentInformation(bytes)).toString());
				break;
			case OptionFormat.clientIdentifier:
				enforce(bytes.length >= 1, "No type");
				f.writefln("type=%d, clientIdentifier=%s", bytes[0], maybeAscii(bytes[1..$]));
				break;
			case OptionFormat.zeroLength:
				enforce(bytes.length==0, "Expected zero length");
				f.writeln("present");
				break;
		}
	catch (Exception e)
		f.writefln("Decode error (%s). Raw bytes: %s",
			e.msg, maybeAscii(bytes));
}

/// Print an option in machine-readable format.
void printRawOption(File f, in ubyte[] bytes, OptionFormat fmt)
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
			f.writefln("%-(%02X%)", bytes);
			break;
		case OptionFormat.str:
			f.write(cast(char[])bytes);
			f.flush();
			break;
		case OptionFormat.ip:
		case OptionFormat.boolean:
		case OptionFormat.u8:
		case OptionFormat.u16:
		case OptionFormat.u32:
		case OptionFormat.dhcpMessageType:
		case OptionFormat.dhcpOptionType:
		case OptionFormat.netbiosNodeType:
		case OptionFormat.classlessStaticRoute:
			return printOption(f, bytes, fmt);
		case OptionFormat.time:
			return printOption(f, bytes, OptionFormat.u32);
	}
}

