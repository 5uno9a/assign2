package edu.wisc.cs.sdn.vnet.rt;

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

		// 8. ARP lookup for nextHop
		ArpEntry ae = this.arpCache.lookup(nextHop);
		if (ae == null) {
			return; // no ARP entry -> drop (no ARP resolution in this assignment)
		}

		// 9. Rewrite Ethernet header
		MACAddress dstMac = ae.getMac();
		MACAddress srcMac = outIface.getMacAddress();
		if (dstMac == null || srcMac == null) {
			return;
		}

		etherPacket.setDestinationMACAddress(dstMac.toBytes());
		etherPacket.setSourceMACAddress(srcMac.toBytes());

		// 10. Send the packet out
		sendPacket(etherPacket, outIface);


		/********************************************************************/
	}
}
