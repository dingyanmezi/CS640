package edu.wisc.cs.sdn.vnet.rt;
	import java.util.*;
	import java.nio.ByteBuffer;
	import java.util.concurrent.*;
	
	import net.floodlightcontroller.packet.Ethernet; // 最后如果bug找不到可能是因为这个地方没*
	import net.floodlightcontroller.packet.IPv4;
	import edu.wisc.cs.sdn.vnet.Device;
	import edu.wisc.cs.sdn.vnet.DumpFile;
	import edu.wisc.cs.sdn.vnet.Iface;
	
	/**
	* @author Aaron Gember-Jacobson and Anubhavnidhi Abhashkumar
	*/
	public class Router extends Device 
	{
		/** Routing table for the router */
		private RouteTable routeTable;
		
		/** ARP cache for the router */
		private ArpCache arpCache;
		
		private Map<Integer, List<Ethernet>> Arp_Queue;
		private Map<Integer, LocalRipEntry> Rip_Map;

		private final int TIME_EXCEEDED = 0;
		private final int DEST_NET_UNREACHABLE = 1;
		private final int DEST_HOST_UNREACHABLE = 2;
		private final int DEST_PORT_UNREACHABLE = 3;
		private final int ICMP_ECHO_REPLY = 4;

		private final int ARP_REQUEST = 0;
		private final int ARP_REPLY = 1;

		private final int RIP_REQUEST = 0;
		private final int RIP_RESPONSE = 1;
		private final int RIP_UNSOL = 2;

		private final String MAC_BROADCAST = "ff:ff:ff:ff:ff:ff";
		private final String MAC_ZERO = "00:00:00:00:00:00";
		private final String IP_RIP_MULTICAST = "224.0.0.9";



		/**
		* Creates a router for a specific host.
		*
		* @param host
		* hostname for the router
		*/
		public Router(String host, DumpFile logfile) 
		{
			super(host, logfile);
			this.routeTable = new RouteTable();
			this.arpCache = new ArpCache();
			this.Arp_Queue = new ConcurrentHashMap<Integer, List<Ethernet>>();
			this.Rip_Map = new ConcurrentHashMap<Integer, LocalRipEntry>();
		}
		
		/**
		* @return routing table for the router
		*/
		public RouteTable getRouteTable() 
		{
			return this.routeTable;
		}
		
		/**
		* Load a new routing table from a file.
		*
		* @param routeTableFile
		* the name of the file containing the routing table
		*/
		public void loadRouteTable(String routeTableFile) 
		{
			if (!routeTable.load(routeTableFile, this)) 
			{
				System.err.println("Error setting up routing table from file "
				+ routeTableFile);
				System.exit(1);
			}
		
			System.out.println("Loaded static route table");
			System.out.println("-------------------------------------------------");
			System.out.print(this.routeTable.toString());
			System.out.println("-------------------------------------------------");
		}
		
		/**
		* Load a new ARP cache from a file.
		*
		* @param arpCacheFile
		* the name of the file containing the ARP cache
		*/
		public void loadArpCache(String arpCacheFile) 
		{
			if (!arpCache.load(arpCacheFile)) 
			{
				System.err.println("Error setting up ARP cache from file "
				+ arpCacheFile);
				System.exit(1);
			}
			
			System.out.println("Loaded static ARP cache");
			System.out.println("----------------------------------");
			System.out.print(this.arpCache.toString());
			System.out.println("----------------------------------");
		}
		
		/**
		* Handle an Ethernet packet received on a specific interface.
		*
		* @param etherPacket
		* the Ethernet packet that was received
		* @param inIface
		* the interface on which the packet was received
		*/
		public void handlePacket(Ethernet etherPacket, Iface inIface) 
		{
			System.out.println("*** -> Received packet: "+ etherPacket.toString().replace("\n", "\n\t"));

			
			
			if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4) 
			{
				System.out.println("IPv4 check fail");
				return;
			}
			
			IPv4 packet = (IPv4) etherPacket.getPayload();
			short checksum = packet.getChecksum();
			/*******************************************/
			System.out.println(arpCache.toString());

			System.out.println(packet.getDestinationAddress());
			System.out.println(checksum);
			/*******************************************/
			byte ttl = packet.getTtl();
			packet.setChecksum((short) 0);
			byte[] dPacket = packet.serialize();
			packet = (IPv4) packet.deserialize(dPacket, 0, dPacket.length);
			if (packet.getChecksum() != checksum || ttl <= 1) {
			System.out.println("checkum/ttl fail " + checksum + " " + ttl);
			return;
			}
			ttl -= 1;
			packet.setTtl(ttl);
			packet.setChecksum((short) 0);
			dPacket = packet.serialize();
			packet = (IPv4) packet.deserialize(dPacket, 0, dPacket.length);
			etherPacket.setPayload(packet);
			
			for (Iface iface : interfaces.values())
			{
				if (iface.getIpAddress() == packet.getDestinationAddress()) 
				{
					System.out.println("Router Interface drop");
					return;
				}
			}
			
			RouteEntry entry = routeTable.lookup(packet.getDestinationAddress());
			if (entry == null) 
			{
				System.out.println("Route Table lookup fail");
				return;
			}
			
			if (entry.getInterface().getMacAddress().equals(inIface.getMacAddress())) 
			{
				return;
			}
			
			ArpEntry lookup = arpCache.lookup(packet.getDestinationAddress());
			if (lookup == null) 
			{
				System.out.println("Arp fail");
				return;
			}
			
			etherPacket.setDestinationMACAddress(lookup.getMac().toBytes());
			etherPacket.setSourceMACAddress(entry.getInterface().getMacAddress()
			.toBytes());
			
			sendPacket(etherPacket, entry.getInterface());
		}
	}
