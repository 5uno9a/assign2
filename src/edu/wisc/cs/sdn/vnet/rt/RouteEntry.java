package edu.wisc.cs.sdn.vnet.rt;

import edu.wisc.cs.sdn.vnet.Iface;
import net.floodlightcontroller.packet.IPv4;

/**
 * An entry in a route table.
 * @author Aaron Gember-Jacobson and Anubhavnidhi Abhashkumar
 */
public class RouteEntry 
{	
	/** Whether the route is directly connected */
	private boolean isDirect;

	/** Last time the route was updated */
	private long lastUpdated;

	/** Metric for the route (e.g., hop count) */
	private int metric;

	/** Destination IP address */
	private int destinationAddress;
	
	/** Gateway IP address */
	private int gatewayAddress;
	
	/** Subnet mask */
	private int maskAddress;
	
	/** Router interface out which packets should be sent to reach
	 * the destination or gateway */
	private Iface iface;
	
	/**
	 * Create a new route table entry.
	 * @param destinationAddress destination IP address
	 * @param gatewayAddress gateway IP address
	 * @param maskAddress subnet mask
	 * @param iface the router interface out which packets should 
	 *        be sent to reach the destination or gateway
	 */
	public RouteEntry(int destinationAddress, int gatewayAddress, 
			int maskAddress, Iface iface, boolean isDirect, int metric)
	{
		this.destinationAddress = destinationAddress;
		this.gatewayAddress = gatewayAddress;
		this.maskAddress = maskAddress;
		this.iface = iface;
		this.isDirect = isDirect;
		this.lastUpdated = System.currentTimeMillis();
		this.metric = metric;
	}
	
	/**
	 * @return destination IP address
	 */
	public int getDestinationAddress()
	{ return this.destinationAddress; }
	
	/**
	 * @return gateway IP address
	 */
	public int getGatewayAddress()
	{ return this.gatewayAddress; }

	public void setGatewayAddress(int gatewayAddress)
	{ this.gatewayAddress = gatewayAddress; }
	
	/**
	 * @return subnet mask 
	 */
	public int getMaskAddress()
	{ return this.maskAddress; }
	
	/**
	 * @return the router interface out which packets should be sent to 
	 *         reach the destination or gateway
	 */
	public Iface getInterface()
	{ return this.iface; }

	public void setInterface(Iface iface)
	{ this.iface = iface; }
	
	public String toString()
	{
		return String.format("%s \t%s \t%s \t%s",
				IPv4.fromIPv4Address(this.destinationAddress),
				IPv4.fromIPv4Address(this.gatewayAddress),
				IPv4.fromIPv4Address(this.maskAddress),
				this.iface.getName());
	}

	public boolean isDirectRoute() {
		return isDirect;
	}

	public void setDirectRoute(boolean isDirect) {
		this.isDirect = isDirect;
	}

	public long getLastUpdated() {
		return lastUpdated;
	}

	public void refreshLastUpdated() {
		this.lastUpdated = System.currentTimeMillis();
	}

	public int getMetric() {
		return metric;
	}

	public void setMetric(int metric) {
		this.metric = metric;
	}
}
