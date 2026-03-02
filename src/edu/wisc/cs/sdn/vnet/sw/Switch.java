package edu.wisc.cs.sdn.vnet.sw;

import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.MACAddress;

/**
 * @author Aaron Gember-Jacobson
 */
public class Switch extends Device {

    /**
     * MAC forwarding table: MAC -> (output interface, last-seen time).
     */
    private final Map<MACAddress, MacEntry> macTable = new HashMap<>();

    /**
     * One forwarding table entry with aging.
     */
    private static final class MacEntry {

        // Aging timeout to prevent stale mappings when hosts move or disappear.
        private static final Duration TIMEOUT = Duration.ofSeconds(15);

        private Iface iface;
        private Instant lastSeen;

        MacEntry(Iface iface) {
            refresh(iface);
        }

        void refresh(Iface iface) {
            this.iface = iface;
            this.lastSeen = Instant.now();
        }

        boolean isExpired() {
            return Duration.between(lastSeen, Instant.now()).compareTo(TIMEOUT) > 0;
        }

        Iface iface() {
            return iface;
        }
    }

    public Switch(String host, DumpFile logfile) {
        super(host, logfile);
    }

    @Override
    public void handlePacket(Ethernet frame, Iface inIface) {
        System.out.println(
            "*** -> Received packet: " +
                frame.toString().replace("\n", "\n\t")
        );

        // Learn source on every received frame (refreshes timestamp + port).
        learn(frame.getSourceMAC(), inIface);

        MACAddress dst = frame.getDestinationMAC();

        // Broadcast/multicast frames should be flooded.
        if (dst.isBroadcast() || dst.isMulticast()) {
            flood(frame, inIface);
            return;
        }

        Iface outIface = lookup(dst);

        // Unknown/expired destination -> flood.
        if (outIface == null) {
            flood(frame, inIface);
            return;
        }

        // Avoid reflecting a frame back out the ingress interface.
        if (!outIface.equals(inIface)) {
            sendPacket(frame, outIface);
        }
    }

    private void learn(MACAddress src, Iface inIface) {
        MacEntry e = macTable.get(src);
        if (e == null) {
            macTable.put(src, new MacEntry(inIface)); 
        }else {
            e.refresh(inIface);
        }
    }

    /**
     * @return output interface for dst, or null if unknown/expired
     */
    private Iface lookup(MACAddress dst) {
        MacEntry e = macTable.get(dst);
        if (e == null) {
            return null;
        }

        if (e.isExpired()) {
            macTable.remove(dst);
            return null;
        }

        return e.iface();
    }

    private void flood(Ethernet frame, Iface inIface) {
        for (Iface iface : this.interfaces.values()) {
            if (!iface.equals(inIface)) {
                sendPacket(frame, iface);
            }
        }
    }
}
