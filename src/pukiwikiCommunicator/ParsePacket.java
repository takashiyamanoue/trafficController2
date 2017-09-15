package pukiwikiCommunicator;

import java.net.InetAddress;
import java.util.Date;

import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.EthernetPacket.EthernetHeader;
import org.pcap4j.packet.IcmpV4CommonPacket;
import org.pcap4j.packet.IcmpV4InformationRequestPacket;
import org.pcap4j.packet.IcmpV6CommonPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV6ExtHopByHopOptionsPacket;
import org.pcap4j.packet.IpV6Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;
import org.pcap4j.packet.namednumber.TcpPort;
import org.pcap4j.util.MacAddress;

/*
import org.jnetpcap.PcapHeader;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.JMemoryPacket;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.util.resolver.IpResolver;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Arp;
import org.jnetpcap.protocol.network.Icmp;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;
*/
 
public class ParsePacket {
//	static public Ip4 ip = new Ip4();
	public IpV4Packet ipv4=null;
//	static public Ethernet eth = new Ethernet();
	public IpV6Packet ipv6=null;
	
	public EthernetPacket eth=null;
//	public PcapHeader hdr = new PcapHeader(JMemory.POINTER);
//	public JBuffer buf = new JBuffer(JMemory.POINTER);
//	static public Tcp tcp = new Tcp();
	public TcpPacket tcp= null;
//    static public Udp udp = new Udp();
	public UdpPacket udp = null;
//    static public Arp arp = new Arp();
	public ArpPacket arp = null;
//    static public Icmp icmp = new Icmp();
	public IcmpV4CommonPacket icmp = null;
	public IcmpV6CommonPacket icmpv6 = null;
	public IpV6ExtHopByHopOptionsPacket ipv6hopbyhop=null;
//	public final Http http = new Http();
	public String sourceMacString="";
	public String destinationMacString="";
	public String sourceIpString="";
	public String destinationIpString="";
	public String etherString="";
	public String protocol="";
//	public byte[] payload;
	public Packet payload;
	public String ipString="";
	public String payloadString="";
	public String l4String="";
	public long ptime=0;
	public String ptimes="";
	/**/
	public int sport;
	public int dport;
	/**/
	/*
	public TcpPort sport;
	public TcpPort dport;
	*/
	public int[] address = new int[14];
	public String[] states = new String[]{"","","","","",
		                                     "","","","",""};
	public boolean succeeded;
    public synchronized void reParse(){
//    	packet.scan(Ethernet.ID);
    /*
		try{
	    	   packet.scan(Ethernet.ID);
		}
		catch(Exception e){
				System.out.println("ParsePacket scan failed: "+e);
				return;
		}
		*/
    	eth=null;
    	ipv4=null;
    	tcp=null;
    	udp=null;
    	arp=null;
    	icmp=null;
    	ipv6=null;
    	icmpv6=null;
		states[0]="unknown";
		if(packet==null) return;
//			  if (packet.hasHeader(eth)) {
		if(packet.contains(EthernetPacket.class)) {
//				   sourceMacString = FormatUtils.mac(eth.source());
				eth=(EthernetPacket)packet;
				EthernetHeader eph=eth.getHeader();
				MacAddress macDestAddress=eph.getDstAddr();
				MacAddress macSrcAddress=eph.getSrcAddr();
				sourceMacString=macSrcAddress.toString();
//				destinationMacString = FormatUtils.mac(eth.destination());
				destinationMacString=macDestAddress.toString();
//				System.out.printf("#%d: eth.src=%s\n", packet.getFrameNumber(), str);
//				System.out.printf("#%d: eth.src=%s\n", n, smac);
				/*
				   address[0]= 0xff & (eth.source()[2]);
				   address[1]= 0xff & (eth.source()[3]);
				   address[2]= 0xff & (eth.source()[4]);
				   address[3]= 0xff & (eth.source()[5]);
				   address[6]= 0xff & (eth.destination()[2]);
				   address[7]= 0xff & (eth.destination()[3]);
				   address[8]= 0xff & (eth.destination()[4]);
				   address[9]= 0xff & (eth.destination()[5]);	
				   */
				address[0]= 0xff & (macSrcAddress.getAddress()[2]);
				address[1]= 0xff & (macSrcAddress.getAddress()[3]);
				address[2]= 0xff & (macSrcAddress.getAddress()[4]);
				address[3]= 0xff & (macSrcAddress.getAddress()[5]);
				address[6]= 0xff & (macDestAddress.getAddress()[2]);
				address[7]= 0xff & (macDestAddress.getAddress()[3]);
				address[8]= 0xff & (macDestAddress.getAddress()[4]);
				address[9]= 0xff & (macDestAddress.getAddress()[5]);

	    	       sport=0;
	    	       dport=0;
				   etherString=sourceMacString+"->"+destinationMacString+" ";
		}
        if(packet.contains(ArpPacket.class)){
//		if (packet.hasHeader(ip)) {		if(packet.contains(ArpPacket.class)) {
		   try{
		       protocol ="arp";
		       arp=(ArpPacket)(packet.getPayload());
		       ArpPacket.ArpHeader arph=arp.getHeader();
//		       packet.getHeader(arp);
			   address[4]= 0;
			   address[5]= 0;
			   address[10]= 0;
			   address[11]= 0;
//				sourceIpString=FormatUtils.ip(arp.spa());
			   sourceIpString=arph.getSrcProtocolAddr().toString().substring(1);
//				destinationIpString=FormatUtils.ip(arp.tpa());
			   destinationIpString=arph.getDstProtocolAddr().toString().substring(1);
			   /*
				String arpString=arp.hardwareTypeDescription()+
				            " "+arp.operationDescription()+" "
				            +arp.protocolTypeDescription()
				            +" spa-"+sourceIpString
				            +" tpa-"+destinationIpString;
				            */
			   String arpString=arph.getHardwareType().toString()+" "+
				            arph.getOperation().toString()+" "+
					        arph.getProtocolType().toString()+" "+
				            " spa-"+sourceIpString+
				            " tpa-"+destinationIpString;
				states[0]=arpString;
		   }
		   catch(Exception e){
				System.out.println("ParsePacket arp error: "+e);
				return;				 
		   }
	    }
	    else
		if(packet.contains(IpV4Packet.class)) {
			try{
//				   packet.getHeader(ip);
				ipv4=(IpV4Packet)(packet.getPayload());
				IpV4Packet.IpV4Header ip4h=ipv4.getHeader();
				InetAddress ipSrcAddr= ip4h.getSrcAddr();
//				   sourceIpString = FormatUtils.ip(ip.source());
				sourceIpString=ipSrcAddr.toString().substring(1);
//				   destinationIpString = FormatUtils.ip(ip.destination());
				InetAddress ipDstAddr =ip4h.getDstAddr();
//				destinationIpString = ip4h.getDstAddr().toString();
				destinationIpString = ipDstAddr.toString().substring(1);
//				System.out.printf("#%d: ip.src=%s\n", packet.getFrameNumber(), str);
//				System.out.printf("#%d: ip.src=%s\n", n, sip);
				/*
					address[0]= 0xff & (ip.source()[0]);
					address[1]= 0xff & (ip.source()[1]);
					address[2]= 0xff & (ip.source()[2]);
					address[3]= 0xff & (ip.source()[3]);
					address[6]= 0xff & (ip.destination()[0]);
					address[7]= 0xff & (ip.destination()[1]);
					address[8]= 0xff & (ip.destination()[2]);
					address[9]= 0xff & (ip.destination()[3]);	
					*/
				address[0]=0xff & (ipSrcAddr.getAddress()[0]);
				address[1]=0xff & (ipSrcAddr.getAddress()[1]);
				address[2]=0xff & (ipSrcAddr.getAddress()[2]);
				address[3]=0xff & (ipSrcAddr.getAddress()[3]);
				address[6]=0xff & (ipDstAddr.getAddress()[0]);
				address[7]=0xff & (ipDstAddr.getAddress()[1]);
				address[8]=0xff & (ipDstAddr.getAddress()[2]);
				address[9]=0xff & (ipDstAddr.getAddress()[3]);

				    ipString=sourceIpString+"->"+destinationIpString+" ";
			}
			catch(Exception e){
				System.out.println("ParsePacket error ip: "+e);
				return;
			}
//			if(packet.hasHeader(tcp)){
			if(ipv4!=null) {
			if(ipv4.contains(TcpPacket.class)) {
				try {
//		    	          packet.getHeader(tcp);
		            	tcp=(TcpPacket)(ipv4.getPayload());
		            	TcpPacket.TcpHeader tcph=tcp.getHeader();
		    	          try{
//			    	            payload=tcp.getPayload();
		    	        	  payload=tcp.getPayload();
			    	      }
			    	      catch(Exception e){
//			    		        payload=new byte[]{'e','r','r','o','r'};
			    		        System.out.println("ParsePacket get tcpPayload error: "+e);
			    		        return;
			    	      }
		    	          protocol="tcp";
		    	          /*
		    	          sport=tcp.source();
		    	          dport=tcp.destination();
		  				  address[4]= 0xff & (sport>>8);
						  address[5]= 0xff & sport;
						  address[10]= 0xff & (dport>>8);
						  address[11]= 0xff & dport;
				          String flags="-";
				          if(tcp.flags_SYN()) flags=flags+"SYN-";
				          if(tcp.flags_ACK()) flags=flags+"ACK-";
				          if(tcp.flags_PSH()) flags=flags+"PSH-";
				          if(tcp.flags_FIN()) flags=flags+"FIN-";
				          if(tcp.flags_RST()) flags=flags+"RST-";
				          if(tcp.flags_CWR()) flags=flags+"CWR-";
				          if(tcp.flags_URG()) flags=flags+"URG-";
		    	          payloadString=SBUtil.showAsciiInBinary(payload);
		    	          l4String="tcp "+sport+"->"+dport+" "+flags+" "+payloadString;
		  				  states[0]=flags+" "+payloadString;
		  				  */
		    	          sport=tcph.getSrcPort().valueAsInt();
		    	          dport=tcph.getDstPort().valueAsInt();
		    	          address[4]=0xff & (sport>>8);
		    	          address[5]=0xff & (sport);
		    	          address[10]=0xff & (dport>>8);
		    	          address[11]=0xff & dport;
		    	          String flags="-";
		    	          if(tcph.getSyn()) flags=flags+"SYN-";
		    	          if(tcph.getAck()) flags=flags+"ACK-";
		    	          if(tcph.getPsh()) flags=flags+"PSH-";
		    	          if(tcph.getFin()) flags=flags+"FIN-";
		    	          if(tcph.getRst()) flags=flags+"RST-";
		    	          if(tcph.getUrg()) flags=flags+"URG-";
		    	          if(payload!=null)
		    	            try {
		    	               payloadString=SBUtil.showAsciiInBinary(payload.getRawData());
		    	            }
		    	            catch(Exception e) {
  	        	               System.out.println("ParsePacket tcp error while Making payload String:"+payload.toString()+":"+e.toString());
  	                        }
		    	          else
		    	        	  payloadString="";
		    	          l4String="tcp "+sport+"->"+dport+" "+flags+" "+payloadString;
		    	          states[0]=flags+" "+payloadString;

		            }
		            catch(Exception e){
		            	System.out.println("ParsePacket tcp error: "+e);
		            	return;
		            }
		    }
		    else
//		    if(packet.hasHeader(udp)){
		    if(ipv4.contains(UdpPacket.class)) {
		            try{
		            	udp=(UdpPacket)(ipv4.getPayload());
//		    	          packet.getHeader(udp);
		            	UdpPacket.UdpHeader udph=udp.getHeader();
		    	          protocol="udp";
		    	          /*
		    	          sport=udp.source();
		    	          dport=udp.destination();
		    	          */
		    	          sport=udph.getSrcPort().valueAsInt();
		    	          dport=udph.getDstPort().valueAsInt();
		    	    
		  				  address[4]= 0xff & (sport>>8);
						  address[5]= 0xff & sport;
						  address[10]= 0xff & dport>>8;
						  address[11]= 0xff & dport;
						  /**/
		    	          
		    	          try{
		    	              payload=udp.getPayload();
		    	          }
		    	          catch(Exception e){
		    		          System.out.println("ParsePacket getUdpPayload error:"+e);
//		    		          payload=new byte[]{'e','r','r','o','r','-','g','e','t','P','a','y','l','o','a','d'};
		    		          return;
		    	          }
		    	          if(payload==null) {
			    	          l4String="udp "+sport+"->"+dport+" (no payload)";
			    	          payloadString="(no payload)";
			    	          states[0]=payloadString;		    	        	  
		    	          }
		    	          else {
			    	          l4String="udp "+sport+"->"+dport+" "+SBUtil.showAsciiInBinary(payload.getRawData());
			    	          payloadString=SBUtil.showAsciiInBinary(payload.getRawData());
			    	          states[0]=payloadString;
		    	          }
		            }
		            catch(Exception e){
		            	System.out.println("ParsePacket udp error: "+e);
		            	return;
		            }
		    }
		    else
//		  	if(packet.hasHeader(icmp)){
		    if(ipv4.contains(IcmpV4CommonPacket.class))
		  			try{
//		  				  packet.getHeader(icmp);
		  				icmp = (IcmpV4CommonPacket)(ipv4.getPayload());
						  protocol ="icmp";
						  address[4]= 0;
						  address[5]= 0;
						  address[10]= 0;
						  address[11]= 0;
//						  String icmpString=icmp.checksumDescription();
						  String icmpString=icmp.getHeader().getCode().toString();
						  try {
						     payload=icmp.getPayload();
						  }
						  catch(Exception e) {
						  }
						  if(payload!=null) {
						     payloadString=SBUtil.showAsciiInBinary(payload.getRawData());
						     states[0]=icmpString+" "+payloadString;
						  }
						  else {
							  states[0]=icmpString+" (icmpv4- no payload)";
						  }
					 }
		  			catch(Exception e){
		  				System.out.println("ParsePacket error icmp:"+e);
		  				return;
		  			}
			}
			else{
					try{
						  protocol ="ip-N/A";
						  sport=0;
						  dport=0;
						  payload=ipv4.getPayload();
						  payloadString=SBUtil.showAsciiInBinary(payload.getRawData());
						  states[0]=payloadString;
					}
					catch(Exception e){
						System.out.println("ParsePacket error ip-n/a: "+e);
						return;
					}
			}			
	    }
		else 
		if(packet.contains(IpV6Packet.class)) {
			try{
//				   packet.getHeader(ip);
				ipv6=(IpV6Packet)(packet.getPayload());
				IpV6Packet.IpV6Header ip6h=ipv6.getHeader();
				InetAddress ipSrcAddr= ip6h.getSrcAddr();
//				   sourceIpString = FormatUtils.ip(ip.source());
				sourceIpString=ipSrcAddr.toString().substring(1);
//				   destinationIpString = FormatUtils.ip(ip.destination());
				InetAddress ipDstAddr =ip6h.getDstAddr();
//				destinationIpString = ip4h.getDstAddr().toString();
				destinationIpString = ipDstAddr.toString().substring(1);
//				System.out.printf("#%d: ip.src=%s\n", packet.getFrameNumber(), str);
//				System.out.printf("#%d: ip.src=%s\n", n, sip);
				/*
					address[0]= 0xff & (ip.source()[0]);
					address[1]= 0xff & (ip.source()[1]);
					address[2]= 0xff & (ip.source()[2]);
					address[3]= 0xff & (ip.source()[3]);
					address[6]= 0xff & (ip.destination()[0]);
					address[7]= 0xff & (ip.destination()[1]);
					address[8]= 0xff & (ip.destination()[2]);
					address[9]= 0xff & (ip.destination()[3]);	
					*/
				address[0]=0xff & (ipSrcAddr.getAddress()[0]);
				address[1]=0xff & (ipSrcAddr.getAddress()[1]);
				address[2]=0xff & (ipSrcAddr.getAddress()[2]);
				address[3]=0xff & (ipSrcAddr.getAddress()[3]);
				address[6]=0xff & (ipDstAddr.getAddress()[0]);
				address[7]=0xff & (ipDstAddr.getAddress()[1]);
				address[8]=0xff & (ipDstAddr.getAddress()[2]);
				address[9]=0xff & (ipDstAddr.getAddress()[3]);

				    ipString=sourceIpString+"->"+destinationIpString+" ";
			}
			catch(Exception e){
				System.out.println("ParsePacket error ip: "+e);
				return;
			}
//			if(packet.hasHeader(tcp)){
			if(ipv6!=null) {
			if(ipv6.contains(TcpPacket.class)) {
				try {
//		    	          packet.getHeader(tcp);
		            	tcp=(TcpPacket)(ipv6.getPayload());
		            	TcpPacket.TcpHeader tcph=tcp.getHeader();
		    	          try{
//			    	            payload=tcp.getPayload();
		    	        	  payload=tcp.getPayload();
			    	      }
			    	      catch(Exception e){
//			    		        payload=new byte[]{'e','r','r','o','r'};
			    		        System.out.println("ParsePacket get tcpPayload error: "+e);
			    		        return;
			    	      }
		    	          protocol="tcp";
		    	          /*
		    	          sport=tcp.source();
		    	          dport=tcp.destination();
		  				  address[4]= 0xff & (sport>>8);
						  address[5]= 0xff & sport;
						  address[10]= 0xff & (dport>>8);
						  address[11]= 0xff & dport;
				          String flags="-";
				          if(tcp.flags_SYN()) flags=flags+"SYN-";
				          if(tcp.flags_ACK()) flags=flags+"ACK-";
				          if(tcp.flags_PSH()) flags=flags+"PSH-";
				          if(tcp.flags_FIN()) flags=flags+"FIN-";
				          if(tcp.flags_RST()) flags=flags+"RST-";
				          if(tcp.flags_CWR()) flags=flags+"CWR-";
				          if(tcp.flags_URG()) flags=flags+"URG-";
		    	          payloadString=SBUtil.showAsciiInBinary(payload);
		    	          l4String="tcp "+sport+"->"+dport+" "+flags+" "+payloadString;
		  				  states[0]=flags+" "+payloadString;
		  				  */
		    	          sport=tcph.getSrcPort().valueAsInt();
		    	          dport=tcph.getDstPort().valueAsInt();
		    	          address[4]=0xff & (sport>>8);
		    	          address[5]=0xff & (sport);
		    	          address[10]=0xff & (dport>>8);
		    	          address[11]=0xff & dport;
		    	          String flags="-";
		    	          if(tcph.getSyn()) flags=flags+"SYN-";
		    	          if(tcph.getAck()) flags=flags+"ACK-";
		    	          if(tcph.getPsh()) flags=flags+"PSH-";
		    	          if(tcph.getFin()) flags=flags+"FIN-";
		    	          if(tcph.getRst()) flags=flags+"RST-";
		    	          if(tcph.getUrg()) flags=flags+"URG-";
		    	          if(payload!=null)
		    	            try {
		    	               payloadString=SBUtil.showAsciiInBinary(payload.getRawData());
		    	            }
		    	            catch(Exception e) {
	        	               System.out.println("ParsePacket tcp error while Making payload String:"+payload.toString()+":"+e.toString());
	                        }
		    	          else
		    	        	  payloadString="";
		    	          l4String="tcp "+sport+"->"+dport+" "+flags+" "+payloadString;
		    	          states[0]=flags+" "+payloadString;

		            }
		            catch(Exception e){
		            	System.out.println("ParsePacket tcp error: "+e);
		            	return;
		            }
		    }
		    else
//		    if(packet.hasHeader(udp)){
		    if(ipv6.contains(UdpPacket.class)) {
		            try{
		            	udp=(UdpPacket)(ipv6.getPayload());
//		    	          packet.getHeader(udp);
		            	UdpPacket.UdpHeader udph=udp.getHeader();
		    	          protocol="udp";
		    	          /*
		    	          sport=udp.source();
		    	          dport=udp.destination();
		    	          */
		    	          sport=udph.getSrcPort().valueAsInt();
		    	          dport=udph.getDstPort().valueAsInt();
		    	    
		  				  address[4]= 0xff & (sport>>8);
						  address[5]= 0xff & sport;
						  address[10]= 0xff & dport>>8;
						  address[11]= 0xff & dport;
						  /**/
		    	          
		    	          try{
		    	              payload=udp.getPayload();
		    	          }
		    	          catch(Exception e){
		    		          System.out.println("ParsePacket getUdpPayload error:"+e);
//		    		          payload=new byte[]{'e','r','r','o','r','-','g','e','t','P','a','y','l','o','a','d'};
		    		          return;
		    	          }
		    	          l4String="udp "+sport+"->"+dport+" "+SBUtil.showAsciiInBinary(payload.getRawData());
		    	          payloadString=SBUtil.showAsciiInBinary(payload.getRawData());
		    	          states[0]=payloadString;
		            }
		            catch(Exception e){
		            	System.out.println("ParsePacket udp error: "+e);
		            	return;
		            }			
		    }
		    else
//			  	if(packet.hasHeader(icmp)){
			if(ipv6.contains(IcmpV6CommonPacket.class))
			  			try{
//			  				  packet.getHeader(icmp);
			  				icmpv6 = (IcmpV6CommonPacket)(ipv6.getPayload());
							  protocol ="icmpv6";
							  address[4]= 0;
							  address[5]= 0;
							  address[10]= 0;
							  address[11]= 0;
//							  String icmpString=icmp.checksumDescription();
							  String icmpString=icmpv6.getHeader().getCode().toString();
							  payload=icmpv6.getPayload();
							  try {
								     payload=icmp.getPayload();
							  }
							  catch(Exception e) {
							  }
							  if(payload!=null) {
							     payloadString=SBUtil.showAsciiInBinary(payload.getRawData());
							     states[0]=icmpString+" "+payloadString;
							  }
							  else {
								  states[0]=icmpString+" (icmpv6- no payload)";
							  }
			  			}
			  			catch(Exception e){
			  				System.out.println("ParsePacket error icmpv6:"+e);
			  				return;
			  			}
				}
				else
//		  	if(packet.hasHeader(icmp)){
				if(ipv6.contains(IpV6ExtHopByHopOptionsPacket.class)) {
		  			try{
//		  				  packet.getHeader(icmp);
		  				ipv6hopbyhop = (IpV6ExtHopByHopOptionsPacket)(ipv6.getPayload());
						  protocol ="icmpv6hopbyhop";
						  address[4]= 0;
						  address[5]= 0;
						  address[10]= 0;
						  address[11]= 0;
//						  String icmpString=icmp.checksumDescription();
						  String icmpString=ipv6hopbyhop.getHeader().toString();
						  payload=ipv6hopbyhop.getPayload();
						  try {
							     payload=icmp.getPayload();
						  }
						  catch(Exception e) {
						  }
						  if(payload!=null) {
						     payloadString=SBUtil.showAsciiInBinary(payload.getRawData());
						     states[0]=icmpString+" "+payloadString;
						  }
						  else {
							  states[0]=icmpString+" (icmpv6- no payload)";
						  }
		  			}
		  			catch(Exception e){
		  				System.out.println("ParsePacket error icmpv6:"+e);
		  				return;
		  			}
			    }
				else{
					try{
						  protocol ="ipv6-N/A";
						  sport=0;
						  dport=0;
						  payload=ipv6.getPayload();
						  payloadString=SBUtil.showAsciiInBinary(payload.getRawData());
						  states[0]=payloadString;
					}
					catch(Exception e){
						System.out.println("ParsePacket error ipv6-n/a: "+e);
						return;
					}
			   }			
		}
		else {
			try{
				  protocol ="ether -N/A";
				  sport=0;
				  dport=0;
				  payload=eth.getPayload();
				  payloadString=SBUtil.showAsciiInBinary(payload.getRawData());
				  states[0]=payloadString;
			}
			catch(Exception e){
				System.out.println("ParsePacket error ethernet-n/a: "+e);
				return;
			}
	   }			
			// packet is not ip
//		if(packet.hasHeader(arp)){
		
		try{
//			ptime=packet.getCaptureHeader().timestampInMillis();
			ptime=System.currentTimeMillis();
		    ptimes=""+(new Date(ptime));
		}
		catch(Exception e){
			System.out.println("ParsePacket error get timestamp: "+e);
			return;			
		}
		
		states[2]=protocol;
//				states[3]=IP[1];//�ｽ�ｽ�ｽ�ｽ�ｽ�ｽM�ｽ�ｽ�ｽ�ｽ
		states[3]=sourceIpString;
//				states[4]=IP[2];//�ｽ�ｽ�ｽ�ｽ�ｽ�ｽM�ｽ�ｽ�ｽ�ｽ              
		states[4]=destinationIpString;
//				sport=(address[4]<<8)|(address[5]);
//				dport=(address[10]<<8)|(address[11]);
		states[5]=""+sport;
		states[6]=""+dport;
		states[7]=sourceMacString;
		states[8]=destinationMacString;
		succeeded=true;
    }
	
//	public PcapPacket packet;
    public Packet packet;
//	public JMemoryPacket packet;
//	public ParsePacket(PcapPacket p){
    public ParsePacket(Packet p) {
//    public ParsePacket(JMemoryPacket p){
		packet=p;
		succeeded=false;
		try{
		   reParse();
		}
		catch(Exception e){
			System.out.println("PcapPacket.reParse error: "+e);
			succeeded=false;
			return;
		}
		/*
		try{
		packet.scan(Ethernet.ID);		
		}
		catch(Exception e){
			System.out.println("error, PasePacket ... scan:"+e);
		}
		*/

	}

}
