package edu.wisc.cs.sdn.vnet.rt;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Map.Entry;
import java.util.Timer;
import java.util.TimerTask;

import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;
import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.Data;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.ICMP;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.MACAddress;
import net.floodlightcontroller.packet.RIPv2;
import net.floodlightcontroller.packet.RIPv2Entry;
import net.floodlightcontroller.packet.UDP;

/**
 * @author Aaron Gember-Jacobson and Anubhavnidhi Abhashkumar
 */
public class Router extends Device
{	
	private static final int ICMP_PADDING_SIZE = 4;
	private static final int GARBAGE_COLLECT_PERIOD = 1000 ; 
	private static final int UNSOLLICITED_PERIOD = 10*1000 ; //10 sec
	private static final int RIP_INFINITY = 32;
	
	/** Routing table for the router */
	private RouteTable routeTable;

	/** ARP cache for the router */
	private ArpCache arpCache;

	private ArrayList<ArpThread> ArpThreadList;

	/**
	 * Creates a router for a specific host.
	 * @param host hostname for the router
	 */
	public Router(String host, DumpFile logfile)
	{
		super(host,logfile);
		this.routeTable = new RouteTable();
		this.arpCache = new ArpCache();
		this.ArpThreadList = new ArrayList<ArpThread>();
	}

	/**
	 * @return routing table for the router
	 */
	public RouteTable getRouteTable()
	{ return this.routeTable; }

	/**
	 * @set routing table to be dynamic
	 */
	public void setDynamic(){
		this.routeTable.setDynamic();
		timer_clean = new Timer();
		timer_clean.schedule(garbageCollectTask, 0, GARBAGE_COLLECT_PERIOD);
		timer_send=new Timer();
		timer_send.schedule(unsolicitedResponse,0,UNSOLLICITED_PERIOD);
		RIPInit();
	}
	
	/**
	 * Load a new routing table from a file.
	 * @param routeTableFile the name of the file containing the routing table
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
	 * @param arpCacheFile the name of the file containing the ARP cache
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
	 * @param etherPacket the Ethernet packet that was received
	 * @param inIface the interface on which the packet was received
	 */
	public void handlePacket(Ethernet etherPacket, Iface inIface)
	{
		System.out.println("*** -> Received packet: " +
				etherPacket.toString().replace("\n", "\n\t"));

		/********************************************************************/
		/* TODO: Handle packets                                             */

		switch(etherPacket.getEtherType())
		{
		case Ethernet.TYPE_IPv4:
			this.handleIpPacket(etherPacket, inIface);
			break;
		case Ethernet.TYPE_ARP:
			this.handleARPPacket(etherPacket, inIface);
			break;
			// Ignore all other packet types, for now
		}

		/********************************************************************/
	}

	private void handleIpPacket(Ethernet etherPacket, Iface inIface)
	{
		// Make sure it's an IP packet
		if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4)
		{ return; }

		// Get IP header
		IPv4 ipPacket = (IPv4)etherPacket.getPayload();
		System.out.println("Handle IP packet");

		// Verify checksum
		short origCksum = ipPacket.getChecksum();
		ipPacket.resetChecksum();
		byte[] serialized = ipPacket.serialize();
		ipPacket.deserialize(serialized, 0, serialized.length);
		short calcCksum = ipPacket.getChecksum();
		if (origCksum != calcCksum)
		{ return; }

		// Check TTL
		ipPacket.setTtl((byte)(ipPacket.getTtl()-1));
		if (0 == ipPacket.getTtl())
		{
			// A. Timer expired
			sendICMPPacket(ipPacket, inIface, (byte)11, (byte)0);

			return;
		}

		// Reset checksum now that TTL is decremented
		ipPacket.resetChecksum();

		// If the packet is RIP
		if(routeTable.isDynamic()==true 
				&& ipPacket.getProtocol()==IPv4.PROTOCOL_UDP
				&& ipPacket.getDestinationAddress()==IPv4.toIPv4Address("224.0.0.9")){
			UDP udpPacket = (UDP) ipPacket.getPayload();
			if(udpPacket.getDestinationPort()==UDP.RIP_PORT){
				System.out.println("Recieved RIP packet!");
				RIPv2 rip=(RIPv2)udpPacket.getPayload();
				if(rip.getCommand()==RIPv2.COMMAND_REQUEST){
					Ethernet rip_resp=genRipResp(inIface.getIpAddress(),inIface.getMacAddress());
					return;
				}
				if(rip.getCommand()==RIPv2.COMMAND_RESPONSE){
					updateRip(etherPacket,inIface);
				}
			}
		}

		// Check if packet is destined for one of router's interfaces
		for (Iface iface : this.interfaces.values())
		{
			if (ipPacket.getDestinationAddress() == iface.getIpAddress())
			{
				// D. Destination port unreachable
				if(ipPacket.getProtocol() == IPv4.PROTOCOL_TCP ||
						ipPacket.getProtocol() == IPv4.PROTOCOL_UDP){
					sendICMPPacket(ipPacket, inIface, (byte)3, (byte)3);
				}
				else if(ipPacket.getProtocol() == IPv4.PROTOCOL_ICMP){
					ICMP icmp = (ICMP) ipPacket.getPayload();
					if(icmp.getIcmpType() == ICMP.TYPE_ECHO_REQUEST){
						sendICMPPacket(ipPacket, inIface, (byte)0, (byte)0);
					}
				}

				return;
			}
		}

		// Do route lookup and forward
		this.forwardIpPacket(etherPacket, inIface);
	}

	private void forwardIpPacket(Ethernet etherPacket, Iface inIface)
	{
		// Make sure it's an IP packet
		if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4)
		{ return; }
		System.out.println("Forward IP packet");

		// Get IP header
		IPv4 ipPacket = (IPv4)etherPacket.getPayload();
		int dstAddr = ipPacket.getDestinationAddress();

		// Find matching route table entry 
		RouteEntry bestMatch = this.routeTable.lookup(dstAddr);

		// If no entry matched, do nothing
		if (null == bestMatch)
		{
			// B. Destination Unreachable
			sendICMPPacket(ipPacket, inIface, (byte)3, (byte)0);

			return; 
		}

		// Make sure we don't sent a packet back out the interface it came in
		Iface outIface = bestMatch.getInterface();
		if (outIface == inIface)
		{ return; }

		// Set source MAC address in Ethernet header
		etherPacket.setSourceMACAddress(outIface.getMacAddress().toBytes());

		// If no gateway, then nextHop is IP destination
		int nextHop = bestMatch.getGatewayAddress();
		if (0 == nextHop)
		{ nextHop = dstAddr; }

		// Set destination MAC address in Ethernet header
		ArpEntry arpEntry = this.arpCache.lookup(nextHop);
		if (null == arpEntry)
		{
			// B. Destination Unreachable
			sendICMPPacket(ipPacket, inIface, (byte)3, (byte)1);

			return;
		}
		etherPacket.setDestinationMACAddress(arpEntry.getMac().toBytes());

		this.sendPacket(etherPacket, outIface);
	}

	private void sendICMPPacket(IPv4 ipPacket, Iface inIface, byte type, byte code){
		Ethernet ether = new Ethernet();
		IPv4 ip = new IPv4();
		ICMP icmp = new ICMP();
		Data data = new Data();
		ether.setPayload(ip);
		ip.setPayload(icmp);
		icmp.setPayload(data);

		// Ethernet header
		ether.setEtherType(Ethernet.TYPE_IPv4);

		// IP header
		ip.setTtl((byte)64);
		ip.setProtocol(IPv4.PROTOCOL_ICMP);

		if(type == 0){
			ip.setSourceAddress(ipPacket.getDestinationAddress());
		} else {
			ip.setSourceAddress(inIface.getIpAddress());
		}
		ip.setDestinationAddress(ipPacket.getSourceAddress());

		// ICMP header
		icmp.setIcmpType(type);
		icmp.setIcmpCode(code);

		// Data
		if(type == 0){
			ICMP icmpPacket = (ICMP) ipPacket.getPayload();
			byte[] icmpPayload = icmpPacket.getPayload().serialize();

			data.setData(icmpPayload);
		} else {
			byte[] serialized = ipPacket.serialize();

			int headerLen = ipPacket.getHeaderLength() * 4;
			byte[] buf = new byte[ICMP_PADDING_SIZE + headerLen + 8];

			for(int i=0;i<headerLen+8;i++){
				buf[i+ICMP_PADDING_SIZE] = serialized[i];
			}
			data.setData(buf);
		}

		this.forwardIpPacket(ether, null);
	}
	
	
	private void handleARPPacket(Ethernet etherPacket, Iface inIface){
		// Make sure it's an ARP packet
		if (etherPacket.getEtherType() != Ethernet.TYPE_ARP)
		{ return; }

		//get patload
		ARP arpPacket = (ARP)etherPacket.getPayload();
		//get target IP
		int targetIP=ByteBuffer.wrap(arpPacket.getTargetProtocolAddress()).getInt();
		//get source IP
		int sourceIP = ByteBuffer.wrap(arpPacket.getSenderProtocolAddress()).getInt();
		if(inIface.getIpAddress()!= targetIP){
			//
			System.out.println("\nARP packet not for our inIface: "+inIface.toString());
			System.out.println("\nTarget IP: "+IPv4.fromIPv4Address(targetIP));
			return;
		}
		//make reply to Arp request
		if(arpPacket.getOpCode() == ARP.OP_REQUEST){
			//create new arp header
			ARP arpHeader=new ARP();
			arpHeader.setHardwareType(ARP.HW_TYPE_ETHERNET);
			arpHeader.setProtocolType(ARP.PROTO_TYPE_IP);
			arpHeader.setHardwareAddressLength((byte)(Ethernet.DATALAYER_ADDRESS_LENGTH& 0xff));
			arpHeader.setProtocolAddressLength((byte)4);
			arpHeader.setOpCode(ARP.OP_REPLY);
			arpHeader.setSenderHardwareAddress(inIface.getMacAddress().toBytes());
			arpHeader.setSenderProtocolAddress(IPv4.toIPv4AddressBytes(inIface.getIpAddress()));
			arpHeader.setTargetHardwareAddress(arpPacket.getSenderHardwareAddress());
			arpHeader.setTargetProtocolAddress(arpPacket.getSenderProtocolAddress());
			//create Ethernet header
			Ethernet ethHeader=new Ethernet();
			ethHeader.setEtherType(Ethernet.TYPE_ARP);
			ethHeader.setSourceMACAddress(inIface.getMacAddress().toBytes());
			ethHeader.setDestinationMACAddress(etherPacket.getSourceMACAddress());
			//link the headers
			ethHeader.setPayload(arpHeader);
			//send packet
			sendPacket(ethHeader, inIface);

			return;
		}else{
			//process arp replies
			System.out.println("\nProcessing the arp replies");
			//Consider only if ARP cache value for this IP is missing
			if(arpCache.lookup(sourceIP)==null)
			{
				//find the thread with respect to the source IP
				for(int i=0;i<ArpThreadList.size();i++){
					if(ArpThreadList.get(i).IP==sourceIP){
						//check if still active
						if(ArpThreadList.get(i).succ==false){
							ArpThreadList.get(i).setReply(etherPacket, inIface);
							arpCache.insert(new MACAddress(arpPacket.getSenderHardwareAddress()), sourceIP);
							break;
						}else{
							//if time out, remove the thread
							ArpThreadList.remove(i);
							break;
						}
					}
				}
				return;
			}
		}
	}

	/**
	 * 
	 * @param etherPacket
	 * @param outIface
	 * @return
	 */
	 public Ethernet genArpReq(Ethernet etherPacket, Iface outIface)
	{
		IPv4 ipv4Packet = (IPv4)etherPacket.getPayload();
		
		byte [] broadcast= { (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff };
		byte [] targHWAdd={0,0,0,0,0,0};
		
		Ethernet ether = new Ethernet();
		ARP arp = new ARP();
		
		//create Ethernet Header
		ether.setEtherType(Ethernet.TYPE_ARP);
		ether.setSourceMACAddress(outIface.getMacAddress().toBytes());
		ether.setDestinationMACAddress(broadcast);
		
		// create ARP Header
		arp.setHardwareType(ARP.HW_TYPE_ETHERNET);
		arp.setProtocolType(ARP.PROTO_TYPE_IP);
		arp.setHardwareAddressLength((byte)(Ethernet.DATALAYER_ADDRESS_LENGTH & 0xff));
		arp.setProtocolAddressLength((byte)4);
		arp.setOpCode(ARP.OP_REQUEST);
		arp.setSenderHardwareAddress(outIface.getMacAddress().toBytes());
		arp.setSenderProtocolAddress(IPv4.toIPv4AddressBytes(outIface.getIpAddress()));
		arp.setTargetHardwareAddress(targHWAdd);
		
		//Target Protocol is IP of next Hop
		int targetIP;
		RouteEntry routeEntry = routeTable.lookup(ipv4Packet.getDestinationAddress());
		if(routeEntry.getGatewayAddress()==0)
			targetIP=ipv4Packet.getDestinationAddress();
		else
			targetIP=routeEntry.getGatewayAddress();

		arp.setTargetProtocolAddress(targetIP);
		
		//link the header
		ether.setPayload(arp);
		
		return ether;
	}
	/** 
	 * Initiate RIP
	 */
	public void RIPInit(){
		for(Entry<String, Iface> entry : this.interfaces.entrySet()){
			Iface iface = entry.getValue();
			routeTable.insert_rip(iface.getIpAddress()&iface.getSubnetMask(),0,iface.getSubnetMask(),1,iface);
		}
		for(Entry<String, Iface> entry : this.interfaces.entrySet()){
			Iface iface = entry.getValue();
			sendPacket(genRipReq(iface.getIpAddress(),iface.getMacAddress()), entry.getValue());
		}
		System.out.println("Initiated dynamic route table");
		System.out.println("-------------------------------------------------");
		System.out.print(this.routeTable.toString());
		System.out.println("-------------------------------------------------");
	}
	/** 
	 * generate a RIP response packet
	 * 
	 * @param srcIP
	 * @param srcMAC
	 * @return
	 */
	public Ethernet genRipResp(int srcIP, MACAddress srcMAC){
		Ethernet ether = new Ethernet();
		IPv4 ip = new IPv4();
		UDP udp = new UDP();
		RIPv2 rip = new RIPv2();

		//ethernet layer
		ether.setEtherType(Ethernet.TYPE_IPv4);
		ether.setDestinationMACAddress("FF:FF:FF:FF:FF:FF");
		ether.setSourceMACAddress(srcMAC.toBytes());

		//ip layer
		ip.setSourceAddress(srcIP);
		ip.setDestinationAddress("224.0.0.9");
		ip.setProtocol(IPv4.PROTOCOL_UDP);

		//udp layer
		udp.setSourcePort(UDP.RIP_PORT);
		udp.setDestinationPort(UDP.RIP_PORT);
		
		for(RouteEntry entry : routeTable.getEntries()){
			RIPv2Entry tmp=new RIPv2Entry(entry.getDestinationAddress(),entry.getMaskAddress(),entry.getDistance());
			tmp.setNextHopAddress(entry.getDestinationAddress());
			rip.addEntry(tmp);
		}
		rip.setCommand(RIPv2.COMMAND_RESPONSE);
		
		//link packets together
		ether.setPayload(ip);
		ip.setPayload(udp);
		udp.setPayload(rip);
		
		//reset checksums
		udp.resetChecksum();
		ip.resetChecksum();
		ether.resetChecksum();
		
		return ether;
	}
	
	/** 
	 * generate a RIP request packet
	 * @param srcIP
	 * @param srcMAC
	 * @return
	 */
	public Ethernet genRipReq(int srcIP, MACAddress srcMAC){
		Ethernet ether = new Ethernet();
		IPv4 ip = new IPv4();
		UDP udp = new UDP();
		RIPv2 rip = new RIPv2();

		//ethernet layer
		ether.setEtherType(Ethernet.TYPE_IPv4);
		ether.setDestinationMACAddress("FF:FF:FF:FF:FF:FF");
		ether.setSourceMACAddress(srcMAC.toBytes());

		//ip layer
		ip.setSourceAddress(srcIP);
		ip.setDestinationAddress("224.0.0.9");
		ip.setProtocol(IPv4.PROTOCOL_UDP);

		//udp layer
		udp.setSourcePort(UDP.RIP_PORT);
		udp.setDestinationPort(UDP.RIP_PORT);
		
		rip.setCommand(RIPv2.COMMAND_REQUEST);
		
		//link packets together
		ether.setPayload(ip);
		ip.setPayload(udp);
		udp.setPayload(rip);
		
		//reset checksums
		udp.resetChecksum();
		ip.resetChecksum();
		ether.resetChecksum();
		
		return ether;
	}
	
	/**
	 * 
	 */
	public void broadRIPReq(){
		for(Entry<String, Iface> entry : this.interfaces.entrySet()){
			Iface iface = entry.getValue();
			sendPacket(genRipReq(iface.getIpAddress(),iface.getMacAddress()), entry.getValue());
		}
	}

	/**
	 * Update the dynamic route table according to the incoming RIP packet
	 * @param ether
	 * @param inIface
	 */
	public synchronized void updateRip(Ethernet ether,Iface inIface){
		IPv4 packet = (IPv4) ether.getPayload();
		UDP udpPacket = (UDP) packet.getPayload();
		RouteEntry inEntry=routeTable.lookup(packet.getSourceAddress());
		if(inEntry==null){
			return;
		}
		RIPv2 rip= (RIPv2) udpPacket.getPayload();
		for(RIPv2Entry ripEntry : rip.getEntries()){
			RouteEntry routeEntry=routeTable.lookup(ripEntry.getAddress());
			//If the term in RIP is not in the table
			if(routeEntry==null){
				routeTable.insert_rip(ripEntry.getAddress()&ripEntry.getSubnetMask(),packet.getSourceAddress(),ripEntry.getSubnetMask(),ripEntry.getMetric()+1,inIface);
			}else{
				if(routeEntry.getDistance()>ripEntry.getMetric()+inEntry.getDistance()+1){
					routeTable.update_rip(ripEntry.getAddress()&ripEntry.getSubnetMask(), ripEntry.getSubnetMask(), packet.getSourceAddress() ,Math.max(ripEntry.getMetric()+inEntry.getDistance(),RIP_INFINITY),inIface);
				}else{
					//Update the time
					routeTable.update_time(ripEntry.getAddress()&ripEntry.getSubnetMask(),ripEntry.getSubnetMask());
				}
			}
		}
		System.out.println("Updated dynamic route table");
		System.out.println("-------------------------------------------------");
		System.out.print(this.routeTable.toString());
		System.out.println("-------------------------------------------------");
	}
	

	private Timer timer_clean,timer_send;
	private TimerTask garbageCollectTask = new TimerTask() {
		@Override
		public void run() {
			routeTable.cleanTable();
		}
	};
	private TimerTask unsolicitedResponse = new TimerTask() {
		@Override
		public void run() {
			for(Entry<String, Iface> entry : interfaces.entrySet()){
				Iface iface = entry.getValue();
				sendPacket(genRipResp(iface.getIpAddress(),iface.getMacAddress()), entry.getValue());
			}
		}
	};
}