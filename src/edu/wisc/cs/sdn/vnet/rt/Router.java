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
 * Virtual IP router for the CS640 virtual network.
 * Forwards IPv4 using the route table and static ARP; can run RIPv2 when no -r file is given.
 *
 * @author Aaron Gember-Jacobson and Anubhavnidhi Abhashkumar
 */
public class Router extends Device {

	// State
	private boolean ripModeRequested = false;
	private boolean ripEnabled = false;
	private Timer ripTimer;
	private Timer ripStartRetryTimer;
	private RouteTable routeTable;
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
        System.out.print(this.routeTable.toString());
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
        System.out.print(this.arpCache.toString());
    }

	// Packet forwarding (IPv4 transit traffic)
	public void handlePacket(Ethernet etherPacket, Iface inIface) {
		tryStartRipIfReady();

		System.out.println(
			"*** -> Received packet: " +
				etherPacket.toString().replace("\n", "\n\t")
		);

		if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4) {
			return;
		}

		IPv4 ip = (IPv4) etherPacket.getPayload();

		short origCksum = ip.getChecksum();
		ip.resetChecksum();
		ip.serialize();
		short computedCksum = ip.getChecksum();
		if (computedCksum != origCksum) {
			return;
		}

		// RIP (UDP 520): handle here, do not forward as data
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

		int ttl = ip.getTtl() & 0xff;
		if (ttl <= 1) {
			return;
		}
		ip.setTtl((byte) (ttl - 1));
		ip.resetChecksum();
		ip.serialize();

		int dstIp = ip.getDestinationAddress();
		for (Iface iface : this.interfaces.values()) {
			if (iface.getIpAddress() == dstIp) {
				return;
			}
		}

		RouteEntry best = this.routeTable.lookup(dstIp);
		if (best == null) {
			return;
		}

		int gw = best.getGatewayAddress();
		int nextHop = (gw != 0) ? gw : dstIp;

		Iface outIface = best.getInterface();
		if (outIface == null) {
			return;
		}

		// Do not send the packet back out the interface it arrived on
		if (outIface == inIface) {
			return;
		}

		ArpEntry ae = this.arpCache.lookup(nextHop);
		if (ae == null) {
			return;
		}

		MACAddress dstMac = ae.getMac();
		MACAddress srcMac = outIface.getMacAddress();
		if (dstMac == null || srcMac == null) {
			System.err.println("Router: dropping packet - null MAC (dst=" + (dstMac == null) + " src=" + (srcMac == null) + ") outIface=" + outIface.getName());
			return;
		}

		etherPacket.setDestinationMACAddress(dstMac.toBytes());
		etherPacket.setSourceMACAddress(srcMac.toBytes());
		sendPacket(etherPacket, outIface);
	}

	// RIP startup (dynamic routes when no static -r table)
	public void setRipModeRequested() {
		this.ripModeRequested = true;
	}

	public void finishRipStartup() {
		tryStartRipIfReady();
		if (this.ripModeRequested && !this.ripEnabled) {
			scheduleRipStartRetries();
		}
	}

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

	// RIP: enable direct routes, request, periodic updates and expiry
	public void tryStartRipIfReady() {
		if (!this.ripModeRequested || this.ripEnabled) {
			return;
		}
		if (this.interfaces.isEmpty() || !allInterfacesFullyConfigured()) {
			return;
		}

		this.ripEnabled = true;

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

	// RIP: interface must be usable before sending
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

	// RIP: build and send advertisements
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

	// RIP: process incoming request or response
	private void handleRipPacket(Ethernet etherPacket, IPv4 ip, UDP udp, Iface inIface) {
		RIPv2 rip = (RIPv2) udp.getPayload();

		if (rip.getCommand() == RIPv2.COMMAND_REQUEST) {
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

	// Shutdown
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

