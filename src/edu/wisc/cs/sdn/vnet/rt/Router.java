package edu.wisc.cs.sdn.vnet.rt;

import java.util.Timer;
import java.util.TimerTask;

import net.floodlightcontroller.packet.RIPv2;
import net.floodlightcontroller.packet.RIPv2Entry;
import net.floodlightcontroller.packet.UDP;
import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.MACAddress;



/**
 * @author Aaron Gember-Jacobson and Anubhavnidhi Abhashkumar
 */
public class Router extends Device {
	/** User asked for RIP (no static -r); start may wait until HW is complete */
	private boolean ripModeRequested = false;

	/** True once RIP is running (direct routes + timer installed) */
	private boolean ripEnabled = false;

	/** Periodic RIP timer (10s advertisements + cleanup) */
	private Timer ripTimer;

	/** Retries RIP startup until all interfaces have MAC/IP/mask (POX timing) */
	private Timer ripStartRetryTimer;	

    /** Routing table for the router */
    private RouteTable routeTable;

    /** ARP cache for the router */
    private ArpCache arpCache;

    /**
     * Creates a router for a specific host.
     * @param host hostname for the router
     */
    public Router(String host, DumpFile logfile) {
        super(host, logfile);
        this.routeTable = new RouteTable();
        this.arpCache = new ArpCache();
    }

    /**
     * @return routing table for the router
     */
    public RouteTable getRouteTable() {
        return this.routeTable;
    }

    /**
     * Load a new routing table from a file.
     * @param routeTableFile the name of the file containing the routing table
     */
    public void loadRouteTable(String routeTableFile) {
        if (!routeTable.load(routeTableFile, this)) {
            System.err.println(
                "Error setting up routing table from file " + routeTableFile
            );
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
    public void loadArpCache(String arpCacheFile) {
        if (!arpCache.load(arpCacheFile)) {
            System.err.println(
                "Error setting up ARP cache from file " + arpCacheFile
            );
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
	public void handlePacket(Ethernet etherPacket, Iface inIface) {
		tryStartRipIfReady();

		System.out.println(
			"*** -> Received packet: " +
				etherPacket.toString().replace("\n", "\n\t")
		);

		// 1. Only handle IPv4 packets
		if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4) {
			return; // drop
		}

		IPv4 ip = (IPv4) etherPacket.getPayload();

		// verify IPv4 checksum using IPv4's own logic
		short origCksum = ip.getChecksum();
		ip.resetChecksum();   // sets checksum field to 0
		ip.serialize();       // recomputes checksum and stores it in ip
		short computedCksum = ip.getChecksum();

		if (computedCksum != origCksum) {
			return;
		}

		/* RIP control-plane packet handling (UDP dst port 520). */
		if (this.ripEnabled
			&& ip.getProtocol() == IPv4.PROTOCOL_UDP
			&& ip.getPayload() instanceof UDP) {
			UDP udp = (UDP) ip.getPayload();
			if (udp.getDestinationPort() == UDP.RIP_PORT
				&& udp.getPayload() instanceof RIPv2) {
				handleRipPacket(etherPacket, ip, udp, inIface);
				return;
			}
		}

		// decrement TTL and recompute checksum again
		int ttl = ip.getTtl() & 0xff;
		if (ttl <= 1) {
			return;
		}
		ip.setTtl((byte) (ttl - 1));

		ip.resetChecksum();
		ip.serialize();

		// 4. Drop packets destined to the router itself
		int dstIp = ip.getDestinationAddress();
		for (Iface iface : this.interfaces.values()) {
			if (iface.getIpAddress() == dstIp) {
				return; // destined to router -> local delivery ignored
			}
		}

		// 5. Route lookup – longest prefix match
		RouteEntry best = this.routeTable.lookup(dstIp);
		if (best == null) {
			return; // no route -> drop
		}

		// 6. Determine next-hop IP
		int gw = best.getGatewayAddress();
		int nextHop = (gw != 0) ? gw : dstIp;

		// 7. Find outgoing interface
		Iface outIface = best.getInterface();
		if (outIface == null) {
			return; // should not happen, but be safe
		}

		/* Never route a packet back out the interface it arrived on. */
		if (outIface == inIface) {
			return;
		}

		// 8. ARP lookup for nextHop
		ArpEntry ae = this.arpCache.lookup(nextHop);
		if (ae == null) {
			return; // no ARP entry -> drop (no ARP resolution in this assignment)
		}

		// 9. Rewrite Ethernet header
		MACAddress dstMac = ae.getMac();
		MACAddress srcMac = outIface.getMacAddress();
		if (dstMac == null || srcMac == null) {
			System.err.println("Router: dropping packet - null MAC (dst=" + (dstMac == null) + " src=" + (srcMac == null) + ") outIface=" + outIface.getName());
			return;
		}

		etherPacket.setDestinationMACAddress(dstMac.toBytes());
		etherPacket.setSourceMACAddress(srcMac.toBytes());

		// 10. Send the packet out
		sendPacket(etherPacket, outIface);


		/********************************************************************/
	}

	/** Enable RIP before VNS_HW_INFO is read (call from Main). */
	public void setRipModeRequested() {
		this.ripModeRequested = true;
	}

	/**
	 * After HW info (and ARP load order), complete RIP startup or schedule retries.
	 */
	public void finishRipStartup() {
		tryStartRipIfReady();
		if (this.ripModeRequested && !this.ripEnabled) {
			scheduleRipStartRetries();
		}
	}

	/** @deprecated use setRipModeRequested + finishRipStartup from Main */
	public void startRip() {
		setRipModeRequested();
		finishRipStartup();
	}

	private void scheduleRipStartRetries() {
		if (this.ripStartRetryTimer != null) {
			return;
		}
		this.ripStartRetryTimer = new Timer(true);
		this.ripStartRetryTimer.scheduleAtFixedRate(new TimerTask() {
			private int attempts;

			@Override
			public void run() {
				tryStartRipIfReady();
				attempts++;
				if (Router.this.ripEnabled || attempts > 200) {
					if (!Router.this.ripEnabled && Router.this.ripModeRequested) {
						System.err.println(
							"Router: RIP could not start; interfaces missing MAC/IP/mask after wait.");
					}
					Router.this.ripStartRetryTimer.cancel();
					Router.this.ripStartRetryTimer = null;
				}
			}
		}, 250, 250);
	}

	/**
	 * Called after VNS_HW_INFO is applied; starts RIP if all interfaces are configured.
	 */
	public void tryStartRipIfReady() {
		if (!this.ripModeRequested || this.ripEnabled) {
			return;
		}
		if (this.interfaces.isEmpty() || !allInterfacesFullyConfigured()) {
			return;
		}

		this.ripEnabled = true;

		// Insert directly connected routes (never expire)
		for (Iface iface : this.interfaces.values()) {
			int subnet = iface.getIpAddress() & iface.getSubnetMask();
			this.routeTable.insertDirect(subnet, iface.getSubnetMask(), iface);
		}

		sendRipRequestAll();

		this.ripTimer = new Timer(true);
		this.ripTimer.scheduleAtFixedRate(new TimerTask() {
			@Override
			public void run() {
				sendRipResponseAll();
				routeTable.cleanExpiredEntries();
			}
		}, 10000, 10000);
	}

	private static boolean isIfaceReadyForRip(Iface iface) {
		return iface != null
			&& iface.getMacAddress() != null
			&& iface.getIpAddress() != 0
			&& iface.getSubnetMask() != 0;
	}

	private boolean allInterfacesFullyConfigured() {
		for (Iface iface : this.interfaces.values()) {
			if (!isIfaceReadyForRip(iface)) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Send a RIP request to multicast destination on each interface.
	 */
	private void sendRipRequestAll() {
		for (Iface outIface : this.interfaces.values()) {
			if (!isIfaceReadyForRip(outIface)) {
				continue;
			}
			RIPv2 rip = new RIPv2();
			rip.setCommand(RIPv2.COMMAND_REQUEST);
			sendRipPacket(rip, outIface, IPv4.toIPv4Address("224.0.0.9"),
				Ethernet.toMACAddress("FF:FF:FF:FF:FF:FF"));
		}
	}

	/**
	 * Send unsolicited RIP responses to multicast destination on each interface.
	 */
	private void sendRipResponseAll() {
		for (Iface outIface : this.interfaces.values()) {
			if (!isIfaceReadyForRip(outIface)) {
				continue;
			}
			RIPv2 rip = buildRipResponsePayload();
			sendRipPacket(rip, outIface, IPv4.toIPv4Address("224.0.0.9"),
				Ethernet.toMACAddress("FF:FF:FF:FF:FF:FF"));
		}
	}

	/**
	 * Build a RIP response containing all known routes.
	 */
	private RIPv2 buildRipResponsePayload() {
		RIPv2 rip = new RIPv2();
		rip.setCommand(RIPv2.COMMAND_RESPONSE);

		for (RouteEntry entry : this.routeTable.getEntries()) {
			RIPv2Entry ripEntry = new RIPv2Entry(
				entry.getDestinationAddress(),
				entry.getMaskAddress(),
				entry.getMetric()
			);
			ripEntry.setNextHopAddress(entry.getGatewayAddress());
			rip.addEntry(ripEntry);
		}

		return rip;
	}

	/**
	 * Send a RIP packet out one interface with provided L2/L3 destination.
	 */
	private void sendRipPacket(RIPv2 rip, Iface outIface, int dstIp, byte[] dstMac) {
		if (!isIfaceReadyForRip(outIface)) {
			return;
		}
		UDP udp = new UDP();
		udp.setSourcePort(UDP.RIP_PORT);
		udp.setDestinationPort(UDP.RIP_PORT);
		udp.setPayload(rip);

		IPv4 ip = new IPv4();
		ip.setTtl((byte) 64);
		ip.setProtocol(IPv4.PROTOCOL_UDP);
		ip.setSourceAddress(outIface.getIpAddress());
		ip.setDestinationAddress(dstIp);
		ip.setPayload(udp);

		Ethernet ether = new Ethernet();
		ether.setEtherType(Ethernet.TYPE_IPv4);
		ether.setSourceMACAddress(outIface.getMacAddress().toBytes());
		ether.setDestinationMACAddress(dstMac);
		ether.setPayload(ip);

		sendPacket(ether, outIface);
	}

	/**
	 * Process incoming RIP request/response.
	 */
	private void handleRipPacket(Ethernet etherPacket, IPv4 ip, UDP udp, Iface inIface) {
		RIPv2 rip = (RIPv2) udp.getPayload();

		if (rip.getCommand() == RIPv2.COMMAND_REQUEST) {
			/* Reply directly to requester (unicast response). */
			RIPv2 response = buildRipResponsePayload();
			sendRipPacket(response, inIface, ip.getSourceAddress(), etherPacket.getSourceMACAddress());
			return;
		}

		if (rip.getCommand() == RIPv2.COMMAND_RESPONSE) {
			int advertiserIp = ip.getSourceAddress();
			for (RIPv2Entry entry : rip.getEntries()) {
				this.routeTable.updateFromRip(
					entry.getAddress(),
					entry.getSubnetMask(),
					advertiserIp,
					entry.getMetric(),
					inIface
				);
			}
		}
	}
	@Override
	public void destroy() {
		if (this.ripTimer != null) {
			this.ripTimer.cancel();
		}
		if (this.ripStartRetryTimer != null) {
			this.ripStartRetryTimer.cancel();
		}
		super.destroy();
	}
}
