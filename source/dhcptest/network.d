module dhcptest.network;

import std.algorithm;
import std.array;
import std.conv;
import std.datetime;
import std.exception;
import std.format;
import std.range;
import std.socket;
import std.string;

import dhcptest.packets;

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

version (linux)
{
	import core.sys.posix.sys.ioctl : ioctl, SIOCGIFINDEX;
	import core.sys.posix.net.if_ : IF_NAMESIZE;

	enum IFNAMSIZ = IF_NAMESIZE;
	extern(C) struct ifreq
	{
		char[IFNAMSIZ] ifr_name = 0;
		union
		{
			private ubyte[IFNAMSIZ] _zeroinit = 0;
			sockaddr       ifr_addr;
			sockaddr       ifr_dstaddr;
			sockaddr       ifr_broadaddr;
			sockaddr       ifr_netmask;
			sockaddr       ifr_hwaddr;
			short          ifr_flags;
			int            ifr_ifindex;
			int            ifr_metric;
			int            ifr_mtu;
		//	ifmap          ifr_map;
			char[IFNAMSIZ] ifr_slave;
			char[IFNAMSIZ] ifr_newname;
			char*          ifr_data;
		}
	}
}

/// Socket pair for DHCP communication
struct DHCPSockets
{
	Socket sendSocket;
	Socket receiveSocket;
	Address sendAddress;
}

immutable targetBroadcast = "255.255.255.255";

/// Parse MAC address from string format (e.g., "01:23:45:67:89:AB")
ubyte[] parseMac(string mac)
{
	return mac.split(":").map!(s => s.parse!ubyte(16)).array();
}

/// Get network interface index by name (Linux only)
version(linux)
int getIfaceIndex(Socket s, string name)
{
	ifreq req;
	auto len = min(name.length, req.ifr_name.length);
	req.ifr_name[0 .. len] = name[0 .. len];
	errnoEnforce(ioctl(s.handle, SIOCGIFINDEX, &req) == 0, "SIOCGIFINDEX failed");
	return req.ifr_ifindex;
}

/// Create and configure sockets for DHCP communication
DHCPSockets createSockets(
	string target,
	ushort serverPort,
	bool useRaw,
	string iface)
{
	DHCPSockets sockets;

	sockets.receiveSocket = new UdpSocket();
	if (target == targetBroadcast)
		sockets.receiveSocket.setOption(SocketOptionLevel.SOCKET, SocketOption.BROADCAST, 1);

	if (useRaw)
	{
		version(linux)
		{
			static if (is(typeof(AF_PACKET)))
			{
				sockets.sendSocket = new Socket(cast(AddressFamily)AF_PACKET, SocketType.RAW, ProtocolType.RAW);

				enforce(iface, "Interface not specified, please specify an interface with --iface");
				auto ifaceIndex = getIfaceIndex(sockets.sendSocket, iface);

				enum ETH_ALEN = 6;
				auto llAddr = new sockaddr_ll;
				llAddr.sll_ifindex = ifaceIndex;
				llAddr.sll_halen = ETH_ALEN;
				llAddr.sll_addr[0 .. 6] = 0xFF;
				sockets.sendAddress = new UnknownAddressReference(cast(sockaddr*)llAddr, sockaddr_ll.sizeof);
			}
			else
				throw new Exception("Raw sockets are not supported on this platform.");
		}
		else
			throw new Exception("Raw sockets are not supported on this platform.");
	}
	else
	{
		sockets.sendSocket = sockets.receiveSocket;
		sockets.sendAddress = new InternetAddress(target, serverPort);
	}

	return sockets;
}

/// Bind receive socket to interface and port
void bindSocket(
	Socket receiveSocket,
	string bindAddr,
	ushort clientPort,
	string iface)
{
	version (linux)
	{
		if (iface)
		{
			enum SO_BINDTODEVICE = cast(SocketOption)25;
			receiveSocket.setOption(SocketOptionLevel.SOCKET, SO_BINDTODEVICE, cast(void[])iface);
		}
	}
	else
		enforce(iface is null, "--iface is not available on this platform");

	receiveSocket.setOption(SocketOptionLevel.SOCKET, SocketOption.REUSEADDR, 1);
	receiveSocket.bind(getAddress(bindAddr, clientPort)[0]);
}

/// Send a DHCP packet via socket
void sendPacket(
	Socket socket,
	Address addr,
	string targetIP,
	ubyte[] mac,
	DHCPPacket packet,
	ushort clientPort,
	ushort serverPort)
{
	auto data = serializePacket(packet);

	// For raw sockets (Linux), wrap DHCP data in Ethernet/IP/UDP headers
	static if (is(typeof(AF_PACKET)))
	if (socket.addressFamily != AF_INET)
		data = buildRawPacketData(data, targetIP, mac, clientPort, serverPort);

	auto sent = socket.sendTo(data, addr);
	errnoEnforce(sent > 0, "sendto error");
	enforce(sent == data.length, "Sent only %d/%d bytes".format(sent, data.length));
}

/// Receive DHCP packets with timeout and handler callback
/// Returns: true if a packet was handled successfully, false if timeout
bool receivePackets(
	Socket socket,
	scope bool delegate(DHCPPacket, Address) handler,
	Duration timeout,
	scope void delegate(string) onError = null)
{
	static ubyte[0x10000] buf;
	Address address;

	SysTime start = Clock.currTime();
	SysTime end = start + timeout;
	auto set = new SocketSet(1);

	while (true)
	{
		auto remaining = end - Clock.currTime();
		if (remaining <= Duration.zero)
			break;

		set.reset();
		set.add(socket);
		int n = Socket.select(set, null, null, remaining);
		enforce(n >= 0, "select interrupted");
		if (!n)
			break; // timeout exceeded

		auto received = socket.receiveFrom(buf[], address);
		if (received <= 0)
			throw new Exception("socket.receiveFrom returned %d.".format(received));

		auto receivedData = buf[0..received].dup;
		try
		{
			auto result = handler(parsePacket(receivedData), address);
			if (!result)
				return true;
		}
		catch (Exception e)
		{
			if (onError)
				onError(format("Error while parsing packet [%(%02X %)]: %s", receivedData, e.toString()));
		}
	}

	// timeout exceeded
	return false;
}
